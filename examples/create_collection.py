# Copyright © 2021 The vt-py authors. All Rights Reserved.
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

"""How to create a collection in VirusTotal."""

import argparse
import json
import vt


def main():
  parser = argparse.ArgumentParser(description='Creates a collection.')
  parser.add_argument('--apikey', required=True, help='your VirusTotal API key')
  parser.add_argument('--name', required=True, help='the collection\'s name')

  args = parser.parse_args()
  client = vt.Client(args.apikey)

  # There are two ways of creating a collection. The first one is using a text
  # that contains one of more IoCs. We could for example load a file for this:
  # with open('file.txt') as f:
  #   col_obj = client.create_collection_from_raw_text(args.name, f.read())

  # The other one is using a list of IoCs (file hashes, URLs, domains and IP
  # addresses). The advantage of this is that these IoCs are validated, so you
  # get an error if for example a domain is not valid or if a file hash doesn't
  # match a MD5/SHA1/SHA256 hash.

  files = []  # Your hashes here.
  urls = []  # Your URLs here.
  domains = ['hooli.com']  # Your domains here.
  ip_addresses = []  # You IP addresses here.

  col_obj = client.create_collection_from_iocs(
      args.name, files=files, urls=urls, domains=domains,
      ip_addresses=ip_addresses)
  client.close()

  print(json.dumps(col_obj.to_dict(), indent=2))
  print('https://www.virustotal.com/gui/collection/%s' % col_obj.id)


if __name__ == '__main__':
  main()
