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


def create_collection_from_raw_text(client, name, raw, **kwargs):
  """Creates a collection in VirusTotal from raw text.

  The collection's IoCs will be extracted the given raw text.

  Args:
    client: VirusTotal client.
    name: Name of the collection.
    raw: Raw text.
    **kwargs: Other attributes that can be added to the collection,
      like for example, the description.

  Returns:
    The new collection.

  Raises:
    ValueError: If the name is empty.
    vt.error.APIError: If there are no IoCs in the raw text.
  """
  if not name:
    raise ValueError('No name provided')
  attributes = {'name': name}
  attributes.update(kwargs)
  payload = {
      'attributes': attributes,
      'type': 'collection',
      'meta': {'raw': raw},
      'id': '',
  }
  collection_obj = vt.Object.from_dict(payload)
  return client.post_object('/collections', obj=collection_obj)

def create_collection_from_iocs(
    client, name, files=None, urls=None, domains=None, ip_addresses=None,
    **kwargs):
  """Creates a collection in VirusTotal from list of IoCs.

  Args:
    client: VirusTotal client.
    name: Name of the collection.
    files: List of file hashes.
    urls: List of URLs.
    domains: List of domains.
    ip_addresses: List of IP addresses.
    **kwargs: Other attributes that can be added to the collection,
      like for example, the description.

  Returns:
    The new collection.

  Raises:
    ValueError: If the name is empty or there are no IoCs to add to the
      collection.
    vt.error.APIError: If any of the IoCs provided are not valid.
  """
  if not name:
    raise ValueError('No name provided')
  attributes = {'name': name}
  attributes.update(kwargs)
  relationships = {}
  if files:
    descriptors = []
    for file_hash in files:
      descriptors.append({'type': 'file', 'id': file_hash})
    relationships['files'] = {'data': descriptors}
  if urls:
    descriptors = []
    for url in urls:
      descriptors.append({'type': 'url', 'url': url})
    relationships['urls'] = {'data': descriptors}
  if domains:
    descriptors = []
    for domain in domains:
      descriptors.append({'type': 'domain', 'id': domain})
    relationships['domains'] = {'data': descriptors}
  if ip_addresses:
    descriptors = []
    for ip_address in ip_addresses:
      descriptors.append({'type': 'ip_address', 'id': ip_address})
    relationships['ip_addresses'] = {'data': descriptors}
  if not relationships:
    raise ValueError('No IoCs provided')

  payload = {
      'attributes': attributes,
      'type': 'collection',
      'relationships': relationships,
      'id': '',
  }
  collection_obj = vt.Object.from_dict(payload)
  return client.post_object('/collections', obj=collection_obj)


def main():
  parser = argparse.ArgumentParser(description='Creates a collection.')
  parser.add_argument('--apikey', required=True, help='your VirusTotal API key')
  parser.add_argument('--name', required=True, help='the collection\'s name')

  args = parser.parse_args()
  client = vt.Client(args.apikey)

  # There are two ways of creating a collection. The first one is using a text
  # that contains one of more IoCs. We could for example load a file for this:
  # with open('file.txt') as f:
  #   collection = create_collection_from_raw_text(client, args.name, f.read())

  # The other one is using a list of IoCs (file hashes, URLs, domains and IP
  # addresses). The advantage of this is that these IoCs are validated, so you
  # get an error if for example a domain is not valid or if a file hash doesn't
  # match a MD5/SHA1/SHA256 hash.

  files = []  # Your hashes here.
  urls = []  # Your URLs here.
  domains = ['hooli.com']  # Your domains here.
  ip_addresses = []  # You IP addresses here.

  col_obj = create_collection_from_iocs(
      client, args.name, files=files, urls=urls, domains=domains,
      ip_addresses=ip_addresses)
  client.close()

  print(json.dumps(col_obj.to_dict(), indent=2))
  print('https://www.virustotal.com/gui/collection/%s' % col_obj.id)


if __name__ == '__main__':
  main()
