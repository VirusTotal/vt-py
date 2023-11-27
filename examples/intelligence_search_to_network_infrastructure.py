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

"""VT Intelligence searches to network IoCs.

This is a script to showcase how programmatic VT Intelligence searches can be
combined with file sandbox behaviour lookups in order to generate network
indicators of compromise that can be fed into network perimeter defenses.

Read more:
https://www.virustotal.com/gui/intelligence-overview
https://docs.virustotal.com/reference/search
https://docs.virustotal.com/docs/virustotal-intelligence-introduction
"""

import argparse
import asyncio
from collections import defaultdict
import re

import vt


class VTISearchToNetworkInfrastructureHandler:
  """Class for handling the process of analysing VTI search matches."""

  _SEARCH_ENTITY_REGEX = re.compile(r"entity: (\w+)")

  def __init__(self, apikey):
    self.apikey = apikey
    self.queue = asyncio.Queue()
    self.files_queue = asyncio.Queue()

    self.networking_counters = {
        "domains": defaultdict(lambda: 0),
        "ips": defaultdict(lambda: 0),
        "urls": defaultdict(lambda: 0),
    }
    self.networking_infrastructure = defaultdict(
        lambda: defaultdict(lambda: {})
    )

  async def get_file_async(self, checksum, relationships=None):
    """Look up a file object."""
    url = "/files/{}"
    async with vt.Client(self.apikey) as client:
      if isinstance(relationships, str) and relationships:
        url += f"?relationships={relationships}"
      file_obj = await client.get_object_async(url.format(checksum))

    return file_obj

  async def get_matching_files(self, query, max_files):
    """Query intelligence for files matching the given criteria."""
    if not isinstance(query, str):
      raise ValueError("Search filter must be a string.")

    entity_match = self._SEARCH_ENTITY_REGEX.match(query.lower())
    if entity_match and entity_match.group(1) != "file":
      raise ValueError("Only file search queries are valid in this example.")

    async with vt.Client(self.apikey) as client:
      query = query.lower()
      url = "/intelligence/search"

      print("Performing VT Intelligence search...")

      files = client.iterator(url, params={"query": query}, limit=max_files)
      async for matching_file in files:
        await self.files_queue.put(matching_file.sha256)

      print("Search concluded, waiting on network infrastructure retrieval...")

  async def get_network(self):
    """Retrieve the network infrastructure related to matching files."""
    while True:
      checksum = await self.files_queue.get()
      file_obj = await self.get_file_async(
          checksum, "contacted_domains,contacted_ips,contacted_urls"
      )
      relationships = file_obj.relationships
      contacted_domains = relationships["contacted_domains"]["data"]
      contacted_urls = relationships["contacted_urls"]["data"]
      contacted_ips = relationships["contacted_ips"]["data"]

      await self.queue.put({
          "contacted_addresses": contacted_domains,
          "type": "domains",
          "file": checksum,
      })
      await self.queue.put({
          "contacted_addresses": contacted_ips,
          "type": "ips",
          "file": checksum,
      })
      await self.queue.put({
          "contacted_addresses": contacted_urls,
          "type": "urls",
          "file": checksum,
      })

      self.networking_infrastructure[checksum]["domains"] = contacted_domains
      self.networking_infrastructure[checksum]["ips"] = contacted_ips
      self.networking_infrastructure[checksum]["urls"] = contacted_urls
      self.files_queue.task_done()

  async def build_network(self):
    """Build the stats of the network infrastructure."""
    while True:
      item = await self.queue.get()
      item_type = item["type"]
      for contacted_address in item["contacted_addresses"]:
        if item_type in ("domains", "ips"):
          address = contacted_address["id"]
        else:
          address = contacted_address["context_attributes"]["url"]
        self.networking_counters[item_type][address] += 1
      self.queue.task_done()

  def print_results(self):
    """Pretty print network IoCs for the given VTI search query."""
    print("\n\n=== Results: ===")
    for item in self.networking_infrastructure.items():
      contacted_addr = item[1].values()
      if any(contacted_addr):
        for inf in item[1].items():
          for key in inf[1]:
            k = key["type"].upper()
            v = key.get("context_attributes", {}).get("url") or key.get("id")
            print(f"{k}: {v}")


async def main():
  """Perform a VTI search and extract IoCs for each of the matches."""
  parser = argparse.ArgumentParser(
      description="Generate network IoCs for files matching a VTI query."
  )
  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")
  parser.add_argument(
      "--query", required=True, help="VT Intelligence search query"
  )
  parser.add_argument("--limit", default=10, help="Limit of files to process.")

  args = parser.parse_args()
  handler = VTISearchToNetworkInfrastructureHandler(args.apikey)

  try:
    enqueue_files_task = asyncio.create_task(
        handler.get_matching_files(args.query, int(args.limit))
    )
    _ = asyncio.create_task(handler.get_network())
    _ = asyncio.create_task(handler.build_network())

    await asyncio.gather(enqueue_files_task)

    await handler.files_queue.join()
    await handler.queue.join()

    handler.print_results()
  except Exception as e:  # pylint: disable=broad-except
    print(f"ERROR: {e}")


if __name__ == "__main__":
  asyncio.run(main())
