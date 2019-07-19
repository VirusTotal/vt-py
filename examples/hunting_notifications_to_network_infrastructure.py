#!/usr/local/bin/python
# -*- coding: utf-8 -*-
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

"""
This example program shows how to use the vt-py synchronous API for getting
the VirusTotal file feed. For a more elaborate example that includes the use
of cursors and the asynchronous API see file_feed_async.py.

NOTICE: In order to use this program you will need an API key that has
privileges for using the VirusTotal Feed API.
"""

import argparse
import asyncio
import datetime
from collections import defaultdict

import vt


class HuntingNotificationToNetworkInfrastructureHandler:
  """Class for handling the process of analysing Hunting Notifications."""

  def __init__(self, apikey, ruleset_filter, limit):
    self.apikey = apikey
    self.filter = ruleset_filter
    self.limit_of_files = limit
    self.queue = asyncio.Queue()
    self.files_queue = asyncio.Queue()
    self.networking_counters = {
        'domains': defaultdict(lambda: 0), 'ips': defaultdict(lambda: 0),
        'urls': defaultdict(lambda: 0)}
    self.networking_infrastructure = defaultdict(
        lambda: defaultdict(lambda: {}))

  async def get_hunting_notification_files(self, date_filter):
    """Get files related with the selected Hunting Ruleset.

      Args:
          date_filter: timestamp representing the min notification date of the
            file (a.k.a the date the file was entered into VT and captured by
            the Hunting Ruleset).
    """

    async with vt.Client(self.apikey) as client:
      files = client.get_hunting_notification_files(self.filter,
          self.limit_of_files)
      async for f in files:
        if f.context_attributes['hunting_notification_date'] > date_filter:
          await self.files_queue.put(f.sha256)

  async def get_network_infrastructure(self):
    """Process a file and get its network infrastructure."""

    while True:
      hash = await self.files_queue.get()
      async with vt.Client(self.apikey) as client:
        file_obj = await client.get_file_async(
          hash, 'contacted_domains,contacted_ips,contacted_urls')
        relationships = file_obj.relationships
        contacted_domains = relationships['contacted_domains']['data']
        contacted_ips = relationships['contacted_ips']['data']
        contacted_urls = relationships['contacted_urls']['data']
        await self.queue.put(
            {'contacted_addresses': contacted_domains,
             'type': 'domains',
             'file': hash})
        await self.queue.put(
            {'contacted_addresses': contacted_ips,
             'type': 'ips',
             'file': hash})
        await self.queue.put(
            {'contacted_addresses': contacted_urls,
             'type': 'urls',
             'file': hash})
        self.networking_infrastructure[hash]['domains'] = contacted_domains
        self.networking_infrastructure[hash]['ips'] = contacted_ips
        self.networking_infrastructure[hash]['urls'] = contacted_urls
      self.files_queue.task_done()

  async def build_network_infrastructure(self):
    """Build the statistics about the network infrastructure of a file."""

    while True:
      item = await self.queue.get()
      type = item['type']
      for contacted_address in item['contacted_addresses']:
        if type in ('domains', 'ips'):
          address = contacted_address['id']
        else:
          address = contacted_address['context_attributes']['url']
        self.networking_counters[type][address] += 1
      self.queue.task_done()

  def print_results(self):
    """Print results of the network infrastructure analysis."""

    print('TOP CONTACTED DOMAINS')
    print('Num. Requests\tDomain')
    for domain_tuple in sorted(self.networking_counters['domains'].items(),
        key=lambda x: -x[1]):
      print('{:>12}\t{:>12}'.format(domain_tuple[1], domain_tuple[0]))
    print('TOP CONTACTED IPs')
    print('Num. Requests\tIP')
    for ip_tuple in sorted(self.networking_counters['ips'].items(),
        key=lambda x: -x[1]):
      print('{:>12}\t{:>12}'.format(ip_tuple[1], ip_tuple[0]))
    print('TOP CONTACTED URLs')
    print('Num. Requests\tURL')
    for url_tuple in sorted(self.networking_counters['urls'].items(),
        key=lambda x: -x[1]):
      print('{:>12}\t{:>12}'.format(url_tuple[1], url_tuple[0]))

    print('\nNETWORK INFRASTRUCTURE')
    for file_network in self.networking_infrastructure.items():
      contacted_addresses = file_network[1].values()
      if any(contacted_addresses):
        print('File Hash: {}'.format(file_network[0]))
        for network_inf in file_network[1].items():
          if network_inf[1]:
            print('\t{}'.format(network_inf[0]))
            for address in network_inf[1]:
              if address['type'] in ('domain', 'ip_address'):
                print('\t\t{}'.format(address['id']))
              else:
                print('\t\t{}'.format(address['context_attributes']['url']))


async def main():

  parser = argparse.ArgumentParser(
      description='Get files from the VirusTotal feed.')

  parser.add_argument('--apikey',
      required=True, help='your VirusTotal API key')

  parser.add_argument('--filter',
      default='', help='Name of the ruleset to filter with')

  parser.add_argument('-l', '--limit',
      default=None, help='Limit of files to be analyzed')

  parser.add_argument('-n', '--num-days',
      default=None, help='Number of days to be analyzed (backward)')

  args = parser.parse_args()
  limit = int(args.limit)
  num_days = int(args.num_days)
  limit_date = datetime.date.today() - datetime.timedelta(days=num_days)
  limit_datetime = datetime.datetime.combine(
      limit_date, datetime.datetime.min.time())
  timestamp_to_compare = datetime.datetime.timestamp(limit_datetime)

  loop = asyncio.get_event_loop()
  handler = HuntingNotificationToNetworkInfrastructureHandler(
      args.apikey, args.filter, limit)

  enqueue_files_task = loop.create_task(
      handler.get_hunting_notification_files(timestamp_to_compare))
  network_inf_task = loop.create_task(handler.get_network_infrastructure())
  build_network_inf_task = loop.create_task(
      handler.build_network_infrastructure())

  await asyncio.gather(enqueue_files_task)

  await handler.files_queue.join()
  await handler.queue.join()

  network_inf_task.cancel()
  build_network_inf_task.cancel()

  handler.print_results()


if __name__ == '__main__':
  loop = asyncio.get_event_loop()
  loop.run_until_complete(main())
  loop.close()
