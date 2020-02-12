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
NOTICE: In order to use this program you will need an API key that has
privileges for using the VirusTotal Feed API.

Set an env-var e.g. $VT_API_KEY
"""

import argparse
import json
import os
import vt


def main():

  parser = argparse.ArgumentParser(
      description='Get URLs from the VirusTotal feed. '
      'For each file in the feed a <url_id>.json file is created in the output '
      'directory containing information about the file.')

  parser.add_argument('--apikey',
      required=True, help='your VirusTotal API key')

  parser.add_argument('--output',
      default='./url-feed', help='path to output directory')

  parser.add_argument('--cursor',
      required=False,
      help='cursor indicating where to start')

  args = parser.parse_args()

  if not os.path.exists(args.output):
    os.makedirs(args.output)

  with vt.Client(args.apikey) as client:
    # Iterate over the file feed, one file at a time. This loop doesn't
    # finish, when the feed is consumed it will keep waiting for more files.

    for url_obj in client.feed(vt.FeedType.URLS, cursor=args.cursor):
      # Write the file's metadata into a JSON-encoded file.

      url_path = os.path.join(args.output, url_obj.id)
      with open(url_path + '.json', mode='w') as f:
        f.write(json.dumps(url_obj.to_dict()))

      print(url_obj.id)


if __name__ == '__main__':
  main()
