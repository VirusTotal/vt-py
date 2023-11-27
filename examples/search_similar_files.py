#!/usr/bin/python

"""This example shows how to find similar files to a given one without uploading

it to VirusTotal.

To find similar files, this example computes both imphash and rich pe header
hash locally, and uses both to find similar files posted in VirusTotal.

This example needs the pefile python package:
https://pypi.org/project/pefile/


NOTE: In order to use this script you will need to have access to
VT Intelligence or to the Premium API. Learn more about these services at:
https://www.virustotal.com/gui/intelligence-overview
https://docs.virustotal.com/reference/search
https://www.virustotal.com/learn/
"""

import argparse
import asyncio
import hashlib
import sys
import pefile
import vt


SEARCHES = [
    ("have", "behaviour_network"),
    ("have", "itw"),
    ("tag", "attachment"),
]


def compute_hashes(path):
  """Computes imphash and rich PE."""
  pe = pefile.PE(path)

  imphash = pe.get_imphash()

  rich_data = pe.parse_rich_header()
  # https://github.com/RichHeaderResearch/RichPE/blob/master/rich.py#L467
  rich = hashlib.md5(rich_data["clear_data"]).hexdigest() if rich_data else None

  pe.close()

  return imphash, rich


def detection_rate_str(file_obj):
  """Returns a string representing detection rate."""
  stats = file_obj.last_analysis_stats
  return f'{stats["malicious"]}/{sum(stats.values())}'


async def search_files(
    apikey, numfiles, hash_type, hash_value, search_type, search_value
):
  """Searches files on VirusTotal based on hash and a filter value.

  Args:
    apikey: str, VirusTotal API key.
    numfiles: int, Max number of files to retrieve per search.
    queue: asyncio queue to put results to.
    hash_type: str, Can be either rich_pe_header_hash or imphash.
    hash_value: str, Hash value to search for.
    search_type: str, field to search by. Can be either tag or have.
    search_value: str, value to search by.

  Returns:
    A set with found URLs in the files' relationships
  """
  search = f"{hash_type}: {hash_value} {search_type}: {search_value}"
  urls = set()
  async with vt.Client(apikey) as client:
    it = client.iterator(
        "/intelligence/search",
        params={"query": search, "relationships": "itw_urls,contacted_urls"},
        limit=numfiles,
    )

    async for f in it:
      print(
          f'{f.sha256}\t{f.last_analysis_date.strftime("%Y-%m-%d")}\t'
          f"{detection_rate_str(f)}"
      )

      for rel in f.relationships.values():
        for r in rel["data"]:
          urls.add(r["context_attributes"]["url"])

  return urls


async def main():
  parser = argparse.ArgumentParser(
      description=(
          "Search similar files to a given one without uploading it "
          "to VirusTotal."
      )
  )
  parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")
  parser.add_argument(
      "-n",
      "--numfiles",
      dest="numfiles",
      default=20,
      help="Number of files to search for in every search.",
  )
  parser.add_argument(
      "--path", required=True, help="File path to find similar files to."
  )
  args = parser.parse_args()

  try:
    imphash, rich = compute_hashes(args.path)
  except pefile.PEFormatError:
    print("ERROR: Input file is not a PE.")
    sys.exit(1)

  tasks = []
  print("Files having same imphash or rich PE header hash:")
  for hash_type, hash_val in [
      ("imphash", imphash),
      ("rich_pe_header_hash", rich),
  ]:
    for search_type, search_value in SEARCHES:
      if hash_val is None:
        continue

      tasks.append(
          asyncio.create_task(
              search_files(
                  args.apikey,
                  args.numfiles,
                  hash_type,
                  hash_val,
                  search_type,
                  search_value,
              )
          )
      )

  urls = await asyncio.gather(*tasks)
  urls = set().union(*urls)
  if urls:
    print("\nRelated URLs:\n{}".format("\n\t".join(urls)))


if __name__ == "__main__":
  asyncio.run(main())
