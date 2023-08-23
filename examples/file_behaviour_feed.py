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
  try:
    tags = item.tags
  except AttributeError:
    tags = []

  try:
    processes_created = item.processes_created
  except AttributeError:
    processes_created = []

  if "executes-dropped-file" in tags or "powershell.exe" in "\n".join(
      processes_created
  ):
    print(item.id.split("_")[0])


def main():
  parser = argparse.ArgumentParser(
      description=(
          "Get file behaviour reports from the VirusTotal feed. "
          "Print documents dropping an executable or launching a Powershell."
      )
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")

  parser.add_argument(
      "--cursor", required=False, help="cursor indicating where to start"
  )

  args = parser.parse_args()

  with vt.Client(args.apikey) as client:
    # Iterate over the file behaviour feed, one file at a time.
    # This loop doesn't finish, when the feed is consumed it will keep waiting
    # for more files.

    try:
      for behaviour_obj in client.feed(
          vt.FeedType.FILE_BEHAVIOURS, cursor=args.cursor
      ):
        # process the behaviour_obj
        process_item(behaviour_obj)
    except KeyboardInterrupt:
      print("\nKeyboard interrupt. Closing.")
    finally:
      client.close()


if __name__ == "__main__":
  main()
