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

the VirusTotal file feed. For a more elaborate example that includes the use
of cursors and the asynchronous API see file_feed_async.py.

NOTICE: In order to use this program you will need an API key that has
privileges for using the VirusTotal Feed API.
"""

import argparse
import json
import os
import vt


def main():
  parser = argparse.ArgumentParser(
      description=(
          "Get files from the VirusTotal feed. For each file in the feed a"
          " <sha256>.json file is created in the output directory containing"
          " information about the file. Additionally you can download the"
          " actual file with the --download-files option."
      )
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")

  parser.add_argument(
      "--output", default="./file-feed", help="path to output directory"
  )

  parser.add_argument(
      "--download-files", action="store_true", help="download files"
  )

  parser.add_argument(
      "--cursor", required=False, help="cursor indicating where to start"
  )

  args = parser.parse_args()

  if not os.path.exists(args.output):
    os.makedirs(args.output)

  with vt.Client(args.apikey) as client:
    # Iterate over the file feed, one file at a time. This loop doesn't
    # finish, when the feed is consumed it will keep waiting for more files.
    for file_obj in client.feed(vt.FeedType.FILES, cursor=args.cursor):
      # Write the file's metadata into a JSON-encoded file. The name of the
      # JSON file will be <SHA-256>.json
      file_path = os.path.join(args.output, file_obj.id)
      with open(file_path + ".json", mode="w", encoding="utf-8") as f:
        f.write(json.dumps(file_obj.to_dict()))
      if args.download_files:
        # Download the file and write it to the output directory with the
        # SHA-256 as its name.
        download_url = file_obj.context_attributes["download_url"]
        response = client.get(download_url)
        with open(file_path, mode="wb") as f:
          f.write(response.read())
      print(file_obj.id)


if __name__ == "__main__":
  main()
