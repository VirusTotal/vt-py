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

"""NOTICE: In order to use this program you will need an API key that has

privileges for using the VirusTotal Feed API.

Set an env-var e.g. $VT_API_KEY
"""

import argparse
import vt


def process_item(item):
  """Processes a fetched item from the feed."""
  total_clean = sum(item.last_analysis_stats.values())
  num_spaces = 100 - len(item.url) if len(item.url) < 100 else 10
  print(
      f'{item.url}{" " * num_spaces}'
      f'{item.last_analysis_stats["malicious"]}/{total_clean}'
  )


def main():
  parser = argparse.ArgumentParser(
      description=(
          "Get URLs from the VirusTotal feed. "
          "For each URL in the feed, print its detection ratio."
      )
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")

  parser.add_argument(
      "--cursor", required=False, help="cursor indicating where to start"
  )

  args = parser.parse_args()

  with vt.Client(args.apikey) as client:
    # Iterate over the URL feed, one file at a time. This loop doesn't
    # finish, when the feed is consumed it will keep waiting for more files.

    try:
      for url_obj in client.feed(vt.FeedType.URLS, cursor=args.cursor):
        # process the url_obj
        process_item(url_obj)
    except KeyboardInterrupt:
      print("\nKeyboard interrupt. Closing.")
    finally:
      client.close()


if __name__ == "__main__":
  main()
