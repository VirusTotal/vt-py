#!/usr/local/bin/python
# Copyright © 2019 The vt-py authors. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""This example program shows how to use the vt-py synchronous API for getting

the VirusTotal files that matched a RetroHunt Job in VT.
"""

import argparse
import asyncio
from collections import defaultdict
from datetime import datetime

from utils import dictpath
import vt


class RetroHuntJobToNetworkInfrastructureHandler:
  """Class for handling the process of analysing RetroHunt Jobs."""

  MIN_IN_COMMON = 1

  def __init__(self, apikey):
    self.apikey = apikey
    self.networking_queue = asyncio.Queue()
    self.files_queue = asyncio.Queue()
    self.files_commonalities = {
        "Creation Time": defaultdict(lambda: []),
        "Imphash": defaultdict(lambda: []),
        "Date Signed": defaultdict(lambda: []),
        "Signers": defaultdict(lambda: []),
        "File Version": defaultdict(lambda: []),
    }
    self.networking_counters = {
        "domains": defaultdict(lambda: 0),
        "ips": defaultdict(lambda: 0),
        "urls": defaultdict(lambda: 0),
    }
    self.networking_infrastructure = defaultdict(
        lambda: defaultdict(lambda: {})
    )

  async def get_retrohunt_matching_files(self, retrohunt_job_id, max_files):
    """Get files related with the selected RetroHunt Job.

    :param retrohunt_job_id: Identifier of the RetroHunt Job whose files we want
    to analyze.
    :param max_files: Max. number of files to be analyzed.
    :type retrohunt_job_id: str
    :type max_files: int
    """

    async with vt.Client(self.apikey) as client:
      url = (
          f"/intelligence/retrohunt_jobs/{retrohunt_job_id}/matching_files?"
          "relationships=contacted_domains,contacted_ips,"
          "contacted_urls"
      )
      files = client.iterator(url, limit=max_files)
      async for f in files:
        await self.files_queue.put(f)

  async def get_file_statistics(self):
    """Process a file and get its statistics."""
    while True:
      file_obj = await self.files_queue.get()
      await self.get_network_infrastructure(file_obj)
      await self.get_commonalities(file_obj)
      self.files_queue.task_done()

  async def get_network_infrastructure(self, file_obj):
    """Process a file and get its network infrastructure."""

    file_hash = file_obj.sha256
    relationships = file_obj.relationships
    contacted_domains = relationships["contacted_domains"]["data"]
    contacted_ips = relationships["contacted_ips"]["data"]
    contacted_urls = relationships["contacted_urls"]["data"]
    await self.networking_queue.put({
        "contacted_addresses": contacted_domains,
        "type": "domains",
        "file": file_hash,
    })
    await self.networking_queue.put(
        {"contacted_addresses": contacted_ips, "type": "ips", "file": file_hash}
    )
    await self.networking_queue.put({
        "contacted_addresses": contacted_urls,
        "type": "urls",
        "file": file_hash,
    })
    self.networking_infrastructure[file_hash]["domains"] = contacted_domains
    self.networking_infrastructure[file_hash]["ips"] = contacted_ips
    self.networking_infrastructure[file_hash]["urls"] = contacted_urls

  async def get_commonalities(self, file_obj):
    """Process a file and get the information to be put in common.

    :param file_obj: File object to be processed.
    :type file_obj: `class:Object`
    """
    file_hash = file_obj.sha256
    file_dict = file_obj.to_dict()
    file_signers = dictpath.get_all(
        file_dict, '$.attributes.signature_info["signers details"][*].name'
    )
    creation_dates = dictpath.get_all(file_dict, "$.attributes.creation_date")
    creation_dates = (datetime.fromtimestamp(x) for x in creation_dates)
    imphashes = dictpath.get_all(file_dict, "$.attributes.pe_info.imphash")
    signed_dates = dictpath.get_all(
        file_dict, '$.attributes.signature_info.["signing date"]'
    )
    file_versions = dictpath.get_all(
        file_dict, '$.attributes.signature_info.["file version"]'
    )

    for file_signer in file_signers:
      self.files_commonalities["Signers"][file_signer].append(file_hash)

    for creation_date in creation_dates:
      self.files_commonalities["Creation Time"][creation_date].append(file_hash)

    for imphash in imphashes:
      self.files_commonalities["Imphash"][imphash].append(file_hash)

    for sign_date in signed_dates:
      self.files_commonalities["Date Signed"][sign_date].append(file_hash)

    for file_version in file_versions:
      self.files_commonalities["File Version"][file_version].append(file_hash)

  async def build_network_infrastructure(self):
    """Build the statistics about the network infrastructure of a file."""

    while True:
      item = await self.networking_queue.get()
      item_type = item["type"]
      for contacted_address in item["contacted_addresses"]:
        if item_type in ("domains", "ips"):
          address = contacted_address["id"]
        else:
          address = contacted_address["context_attributes"]["url"]
        self.networking_counters[item_type][address] += 1
      self.networking_queue.task_done()

  def print_results(self):
    """Print results of network infrastructure and commonalities analysis."""

    print("TOP CONTACTED DOMAINS")
    print("Num. Requests\tDomain")
    for domain_tuple in sorted(
        self.networking_counters["domains"].items(), key=lambda x: -x[1]
    ):
      print(f"{domain_tuple[1]:>12}\t{domain_tuple[0]:>5}")
    print("TOP CONTACTED IPs")
    print("Num. Requests\tIP")
    for ip_tuple in sorted(
        self.networking_counters["ips"].items(), key=lambda x: -x[1]
    ):
      print(f"{ip_tuple[1]:>12}\t{ip_tuple[0]:>12}")
    print("TOP CONTACTED URLs")
    print("Num. Requests\tURL")
    for url_tuple in sorted(
        self.networking_counters["urls"].items(), key=lambda x: -x[1]
    ):
      print(f"{url_tuple[1]:>12}\t{url_tuple[0]:>12}")

    print("\nNETWORK INFRASTRUCTURE")
    for file_network in self.networking_infrastructure.items():
      contacted_addresses = file_network[1].values()
      if any(contacted_addresses):
        print(f"File Hash: {file_network[0]}")
        for network_inf in file_network[1].items():
          if network_inf[1]:
            print(f"\t{network_inf[0]}")
            for address in network_inf[1]:
              if address["type"] in ("domain", "ip_address"):
                print(f'\t\t{address["id"]}')
              else:
                print(f'\t\t{address["context_attributes"]["url"]}')

    print("\nCOMMONALITIES BETWEEN FILES")
    for key, commonality in self.files_commonalities.items():
      comm_items = [
          (k, v) for k, v in commonality.items() if len(v) > self.MIN_IN_COMMON
      ]
      if comm_items:
        print(f"{key}")
        for value_in_common, files_having_it_in_common in comm_items:
          value_in_common = str(value_in_common)
          print(f"\t{value_in_common:<32}\tFiles having it in common:")
          for file_hash in files_having_it_in_common:
            print(f'\t{"":<32}\t{file_hash:<32}')


async def main():
  parser = argparse.ArgumentParser(
      description="Get files from the VirusTotal feed."
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")

  parser.add_argument(
      "-l", "--limit", default=None, help="Limit of files to be analyzed"
  )

  parser.add_argument(
      "-r",
      "--retrohunt-job",
      default=None,
      help="Identifier of the RetroHunt job to analyze",
  )

  args = parser.parse_args()
  limit = int(args.limit)

  handler = RetroHuntJobToNetworkInfrastructureHandler(args.apikey)

  enqueue_files_task = asyncio.create_task(
      handler.get_retrohunt_matching_files(args.retrohunt_job, limit)
  )
  _ = asyncio.create_task(handler.get_file_statistics())
  _ = asyncio.create_task(handler.build_network_infrastructure())

  await asyncio.gather(enqueue_files_task)

  await handler.files_queue.join()
  await handler.networking_queue.join()

  handler.print_results()


if __name__ == "__main__":
  asyncio.run(main())
