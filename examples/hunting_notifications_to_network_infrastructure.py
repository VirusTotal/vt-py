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

the VirusTotal files that matched a Hunting Notification Ruleset.
"""

import argparse
import asyncio
from collections import defaultdict
import datetime

import vt


class HuntingNotificationToNetworkInfrastructureHandler:
  """Class for handling the process of analysing Hunting Notifications."""

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

  async def get_hunting_notification_files(
      self, search_filter, date_filter, max_files
  ):
    """Get/Enqueue files related with a certain Hunting Ruleset.

    :param search_filter: filter for getting notifications of a specific
    ruleset.
    :param date_filter: timestamp representing the min notification date of the
    file (a.k.a the date the file was submitted into VT and captured by
    the Hunting Ruleset).
    :param max_files: Max. number of file to be retrieved/analyzed from VT.
    :type search_filter: str
    :type date_filter: int
    :type max_files: int
    """

    async with vt.Client(self.apikey) as client:
      if not isinstance(search_filter, str):
        raise ValueError("Value to filtering with must be a string")

      filter_tag = search_filter.lower()
      url = f"/intelligence/hunting_notification_files?filter={filter_tag}"
      files = client.iterator(url, limit=max_files)
      async for f in files:
        if f.context_attributes["notification_date"] > date_filter:
          await self.files_queue.put(f.sha256)

  async def get_file_async(self, file_hash, relationships=None):
    """Get a file object from VT.

    :param hash: SHA-256, SHA-1 or MD5 hash that describes the
    :param relationships: relationships to be retrieved alongside with the file.
    Different relationship names should be separated by a comma.
    :type file_hash: str
    :type relationships: str
    :return: `class:Object` containing the file information.
    """
    url = f"/files/{file_hash}"
    async with vt.Client(self.apikey) as client:
      if isinstance(relationships, str) and relationships:
        url += f"?relationships={relationships}"

      file_obj = await client.get_object_async(url)
    return file_obj

  async def get_network_infrastructure(self):
    """Process a file and get its network infrastructure."""

    while True:
      file_hash = await self.files_queue.get()
      file_obj = await self.get_file_async(
          file_hash, "contacted_domains,contacted_ips,contacted_urls"
      )
      relationships = file_obj.relationships
      contacted_domains = relationships["contacted_domains"]["data"]
      contacted_ips = relationships["contacted_ips"]["data"]
      contacted_urls = relationships["contacted_urls"]["data"]
      await self.queue.put({
          "contacted_addresses": contacted_domains,
          "type": "domains",
          "file": file_hash,
      })
      await self.queue.put({
          "contacted_addresses": contacted_ips,
          "type": "ips",
          "file": file_hash,
      })
      await self.queue.put({
          "contacted_addresses": contacted_urls,
          "type": "urls",
          "file": file_hash,
      })
      self.networking_infrastructure[file_hash]["domains"] = contacted_domains
      self.networking_infrastructure[file_hash]["ips"] = contacted_ips
      self.networking_infrastructure[file_hash]["urls"] = contacted_urls
      self.files_queue.task_done()

  async def build_network_infrastructure(self):
    """Build the statistics about the network infrastructure of a file."""

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
    """Print results of the network infrastructure analysis."""

    print("TOP CONTACTED DOMAINS")
    print("Num. Requests\tDomain")
    sorted_domains = sorted(
        self.networking_counters["domains"].items(), key=lambda x: -x[1]
    )
    for domain_tuple in sorted_domains:
      print(f"{domain_tuple[1]:>12}\t{domain_tuple[0]:>5}")
    print("TOP CONTACTED IPs")
    print("Num. Requests\tIP")
    sorted_ips = sorted(
        self.networking_counters["domains"].items(), key=lambda x: -x[1]
    )
    for ip_tuple in sorted_ips:
      print(f"{ip_tuple[1]:>12}\t{ip_tuple[0]:>12}")
    print("TOP CONTACTED URLs")
    print("Num. Requests\tURL")
    sorted_urls = sorted(
        self.networking_counters["domains"].items(), key=lambda x: -x[1]
    )
    for url_tuple in sorted_urls:
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


async def main():
  parser = argparse.ArgumentParser(
      description="Get files matching a Hunting Ruleset in VirusTotal."
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")

  parser.add_argument(
      "--filter", default="", help="Name of the ruleset to filter with"
  )

  parser.add_argument(
      "-l", "--limit", default=None, help="Limit of files to be analyzed"
  )

  parser.add_argument(
      "-n",
      "--num-days",
      default=None,
      help="Number of days to be analyzed (backward)",
  )

  args = parser.parse_args()
  limit = int(args.limit)
  num_days = int(args.num_days)
  limit_date = datetime.date.today() - datetime.timedelta(days=num_days)
  limit_datetime = datetime.datetime.combine(
      limit_date, datetime.datetime.min.time()
  )
  timestamp_to_compare = datetime.datetime.timestamp(limit_datetime)

  handler = HuntingNotificationToNetworkInfrastructureHandler(args.apikey)

  enqueue_files_task = asyncio.create_task(
      handler.get_hunting_notification_files(
          args.filter, timestamp_to_compare, limit
      )
  )
  _ = asyncio.create_task(handler.get_network_infrastructure())
  _ = asyncio.create_task(handler.build_network_infrastructure())

  await asyncio.gather(enqueue_files_task)

  await handler.files_queue.join()
  await handler.queue.join()

  handler.print_results()


if __name__ == "__main__":
  asyncio.run(main())
