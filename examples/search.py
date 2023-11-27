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

"""This example program shows how to make VirusTotal Intelligence searches, the

program accepts a query a prints the matching files/URLs.

NOTICE: In order to use this program you will need an API key that has
privileges for using VirusTotal Intelligence.
"""

import argparse
import vt


def main():
  parser = argparse.ArgumentParser(
      description=(
          "Make a VirusTotal Intelligence search and prints the matching"
          " objects."
      )
  )  # pylint: disable=line-too-long

  parser.add_argument(
      "--query",
      type=str,
      required=True,
      nargs="+",
      help="a VirusTotal Intelligence search query.",
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")

  parser.add_argument(
      "--limit",
      type=int,
      required=False,
      help="maximum number of objects that will be retrieved",
      default=50,
  )

  args = parser.parse_args()

  with vt.Client(args.apikey) as client:
    it = client.iterator(
        "/intelligence/search",
        params={"query": " ".join(args.query)},
        limit=args.limit,
    )
    for obj in it:
      print(f"{obj.type}:{obj.id}")


if __name__ == "__main__":
  main()
