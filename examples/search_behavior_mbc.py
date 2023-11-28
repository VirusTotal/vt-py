#!/usr/bin/env python3

"""This example program shows how to search MBC

https://github.com/MBCProject/mbc-markdown

MBC as of 2023 is present in the CAPA tool integrated in VirusTotal

NOTE: In order to use this script you will need to have access to
VT Intelligence or to the Premium API. Learn more about these services at:
https://www.virustotal.com/gui/intelligence-overview
https://docs.virustotal.com/reference/search
https://www.virustotal.com/learn/
"""


import argparse
import asyncio
import datetime
import logging
import sys
import vt

try:
  import yaml
except ModuleNotFoundError:
  print('this example uses "pyyaml" please install it. https://pyyaml.org/')
  sys.exit(1)


LOGGING_LEVEL = logging.INFO  # Modify if you just want to focus on errors
logging.basicConfig(
    level=LOGGING_LEVEL,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)


class FetchMBCHandler:
  """Handler for Downloading files from VT."""

  def __init__(self, apikey, num_files):
    self.apikey = apikey
    self.num_files = num_files
    self.queue = asyncio.Queue()

  async def parse_mbc_from_behavior_report(self, file_hash, behavior_report):
    """Parse MBC rule ID from report."""

    signature_matches = getattr(behavior_report, "signature_matches", None)
    # no signatures
    if not signature_matches:
      return

    for sig_match in signature_matches:
      if sig_match.get("format") != "SIG_FORMAT_CAPA":
        logging.info("unexpected rule format %s", sig_match)
        continue
      rule_src = sig_match.get("rule_src")
      capa_rule = yaml.safe_load(rule_src)
      mbc_entries = capa_rule.get("rule", {}).get("meta", {}).get("mbc", [])
      for mbc in mbc_entries:
        print(f"sha256: {file_hash}  mbc:{mbc}")

  async def fetch_behavior_reports(self):
    """Fetch file behavior reports."""

    async with vt.Client(self.apikey) as client:
      while True:
        file_hash = await self.queue.get()
        # behavior report ID is format SHA256_SandboxName
        # https://docs.virustotal.com/reference/get-file-behaviour-id
        report_id = f"{file_hash}_CAPA"
        behavior_report = await client.get_object_async(
            f"/file_behaviours/{report_id}"
        )
        await self.parse_mbc_from_behavior_report(file_hash, behavior_report)
        self.queue.task_done()

  async def queue_file_hashes(self, search):
    """Retrieve files from VT and enqueue them for being downloaded.

    Args:
      search: VT intelligence search query.
    """
    async with vt.Client(self.apikey) as client:
      it = client.iterator(
          "/intelligence/search", params={"query": search}, limit=self.num_files
      )
      async for file_obj in it:
        await self.queue.put(file_obj.sha256)


async def main():
  """Search behaviour reports with MBC."""

  usage = "usage: prog [options] <intelligence_query/local_file_with_hashes>"
  parser = argparse.ArgumentParser(
      usage=usage,
      description=(
          "Allows you to search the top-n files returned by a given"
          "VirusTotal Intelligence search. Example: "
          "python %prog sandbox_name:CAPA -n 10 --apikey=<your api key>"
      ),
  )

  parser.add_argument(
      "-q",
      "--query",
      type=str,
      nargs="+",
      help="a VirusTotal Intelligence search query.",
  )
  parser.add_argument(
      "-n",
      "--numfiles",
      dest="numfiles",
      default=10,
      help="Number of reports to download",
  )
  parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
  parser.add_argument(
      "-w",
      "--workers",
      dest="workers",
      default=4,
      help="Concurrent workers for downloading reports",
  )
  args = parser.parse_args()

  if not args.apikey:
    parser.error("No API key provided")

  # if query not specified generate default
  if not args.query:
    today = datetime.date.today()
    # Yesterday date
    yesterday = today - datetime.timedelta(days=1)
    # search seen yesterday and newer
    search = "sandbox_name:CAPA and fs:" + yesterday.strftime(
        "%Y-%m-%dT00:00:00+"
    )
  else:
    search = " ".join(args.query)

  search = search.strip().strip("'")
  numfiles = int(args.numfiles)
  workers = int(args.workers)
  api_key = args.apikey
  handler = FetchMBCHandler(api_key, numfiles)

  logging.info("Starting MBC Fetch example")
  logging.info("* VirusTotal Intelligence search: %s", search)
  logging.info("* Number of reports to fetch: %s", numfiles)

  enqueue_files_task = asyncio.create_task(handler.queue_file_hashes(search))

  download_tasks = []
  for _ in range(workers):
    download_tasks.append(asyncio.create_task(handler.fetch_behavior_reports()))

  await asyncio.gather(enqueue_files_task)
  # Wait until all the reports have been queued and downloaded, then cancel
  # tasks that are idle
  await handler.queue.join()


if __name__ == "__main__":
  asyncio.run(main())
