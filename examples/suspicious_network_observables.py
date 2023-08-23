#!/usr/local/bin/python
# Copyright © 2020 The vt-py authors. All Rights Reserved.
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

"""Suspicious sightings given a list of network observables.

This scripts prints suspicious sightings related to a domain or IP address.
The scripts receives a file as input having a domain/IP address per line.
"""

import argparse
import asyncio
import ipaddress
import vt


def is_ip_address(netloc):
  """Checks whether a given value is a IP address or not.

  Args:
    netloc: str, IP address to check.

  Returns:
    True or false
  """
  try:
    ipaddress.ip_address(netloc)
  except ValueError:
    return False
  else:
    return True


def get_detection_rate(stats):
  """Get detection rate as string."""
  return f'{stats["malicious"]}/{sum(stats.values())}'


def print_results(res, netloc):
  """Print results for a given netloc.

  Results are only printed if there's a suspicious sighting.
  """
  if any(x is not None for x, _, _ in res):
    n_spaces = 50 - len(netloc)
    print(
        f'{netloc}{" " * n_spaces}'
        f'{"  ".join(f"{n} detected {t} [max:{m}]" for m, n, t in res if m)}'
    )


async def get_netloc_relationship(apikey, netloc, rel_type):
  """Gets a netloc relationship and returns the highest detection rate."""
  path = "ip_addresses" if is_ip_address(netloc) else "domains"
  async with vt.Client(apikey) as client:
    it = client.iterator(f"/{path}/{netloc}/{rel_type}", limit=20)
    stats = [
        get_detection_rate(f.last_analysis_stats)
        async for f in it
        if f.last_analysis_stats["malicious"]
    ]

    if stats:
      text = rel_type.replace("_", " ")[: -1 if len(stats) <= 1 else None]
      return max(stats), len(stats), text
    else:
      return None, 0, ""


async def get_netloc_report_relationships(loop, apikey, netloc):
  """Gets report and relationships for a given network location."""
  if not netloc:
    return

  tasks = []
  for rel_type in [
      "urls",
      "downloaded_files",
      "communicating_files",
      "referrer_files",
  ]:
    tasks.append(
        loop.create_task(get_netloc_relationship(apikey, netloc, rel_type))
    )

  results = await asyncio.gather(*tasks, return_exceptions=True)
  print_results(results, netloc)


def main():
  parser = argparse.ArgumentParser(
      description="Get suspicious sightings related to a network observable."
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")
  parser.add_argument(
      "--path",
      required=True,
      type=argparse.FileType("r"),
      help="path to the file containing the domains and IPs.",
  )
  parser.add_argument(
      "--limit",
      type=int,
      default=20,
      help="number of items to process in every search.",
  )
  args = parser.parse_args()

  loop = asyncio.get_event_loop()
  tasks = []
  for n in args.path:
    tasks.append(
        loop.create_task(
            get_netloc_report_relationships(loop, args.apikey, n.strip())
        )
    )

  # Wait until all tasks are completed.
  loop.run_until_complete(asyncio.gather(*tasks))
  loop.close()


if __name__ == "__main__":
  main()
