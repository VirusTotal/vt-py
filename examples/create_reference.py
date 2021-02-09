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

"""
This example program explains how to generate a reference in VirusTotal
and add IOCs to it.

NOTICE: In order to use this program you will need an API key that has
privileges for creating References.
"""

import argparse
import vt
import json

def create_reference(url, creation_date, title, author, iocs, client):
  """ Creates a reference in VirusTotal.

  Args:
    url: Reference url.
    creation_date: Reference creation date (YY-MM-DD HH:mm:ss).
    title: Reference title.
    author: Author
    iocs: List of IOCs. Each IOC must be a dict with type and (id|url). E.g:
      {'type': 'file', 'id': '4c3499f3cc4a4fdc7e67417e055891c78540282dccc57e37a01167dfe351b244'}
      {'type': "url", 'url': "http://www.colasprint.com/_vti_log/upload.asp"},
      {'type': "domain", 'id': "opsonew3org.sg"},
      {'type': "ip_address", 'id': '8.8.8.8'}
    client: VirusTotal client.

  """

  # Generate url identifier
  payload = {
      'data': {
          'attributes': {
              'url': url,
              'creation_date': creation_date,
              'title': title,
              'author': author
          },
          'relationships': {},
          'type': 'reference'
      }
  }

  # Add IOCs to Reference.
  add_iocs_to_reference_payload(iocs, payload)

  # Post object
  client.post('/references', data = json.dumps(payload))

def add_iocs_to_reference_payload(iocs, reference_payload):
  """Adds IOCs relationships to a given reference.

  Args:
    iocs: List of IOCs. Each IOC must be a dict with type and (id|url). E.g:
      {'type': 'file', 'id': '4c3499f3cc4a4fdc7e67417e055891c78540282dccc57e37a01167dfe351b244'}
      {'type': "url", 'url': "http://www.colasprint.com/_vti_log/upload.asp"},
      {'type': "domain", 'id': "opsonew3org.sg"},
      {'type': "ip_address", 'id': '8.8.8.8'}
    reference_payload: Reference payload

  """

  # Groups ioc by types
  files = [ioc for ioc in iocs if ioc['type'] == 'file']
  domains = [ioc for ioc in iocs if ioc['type'] == 'domain']
  urls = [ioc for ioc in iocs if ioc['type'] == 'url']
  ip_addresses = [ioc for ioc in iocs if ioc['type'] == 'ip_address']

  relationship_items = [files, domains, urls, ip_addresses]
  relationship_names = ['files', 'domains', 'urls', 'ip_addresses']

  # Iterate through all relationship types.
  for relationships, relationship_name in zip(
      relationship_items, relationship_names):

    reference_payload['data']['relationships'][relationship_name] = relationships

def main():
  parser = argparse.ArgumentParser(
      description='Create references and add IOCs to them.')

  parser.add_argument('--apikey', required=True, help='your VirusTotal API key')

  args = parser.parse_args()
  API_KEY = args.apikey

  url = 'https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/'

  client = vt.Client(API_KEY)

  # IOCs must specify their type and ID.
  # For urls, instead of "id", "url" field is specified.
  # Allowed types : ['file', 'domain', 'url', ip_address']
  iocs = [
      {'type': 'file', 'id': '4c3499f3cc4a4fdc7e67417e055891c78540282dccc57e37a01167dfe351b244'},
      {'type': 'file', 'id': '68e6b9d71c727545095ea6376940027b61734af5c710b2985a628131e47c6af7'},
      {'type': 'file', 'id': '25d8ae4678c37251e7ffbaeddc252ae2530ef23f66e4c856d98ef60f399fa3dc'},
      {'type': 'file', 'id': 'a75886b016d84c3eaacaf01a3c61e04953a7a3adf38acf77a4a2e3a8f544f855'},
      {'type': 'file', 'id': 'a4fb20b15efd72f983f0fb3325c0352d8a266a69bb5f6ca2eba0556c3e00bd15'},
      {'type': 'url', 'url': 'a4fb20b15efd72f983f0fb3325c0352d8a266a69bb5f6ca2eba0556c3e00bd15'},
      {'type': "url", 'url': "https://angeldonationblog.com/image/upload/upload.php"},
      {'type': "url", 'url': "https://codevexillium.org/image/download/download.asp"},
      {'type': "url", 'url': "https://investbooking.de/upload/upload.asp"},
      {'type': "url", 'url': "https://transplugin.io/upload/upload.asp"},
      {'type': "url", 'url': "https://www.dronerc.it/forum/uploads/index.php"},
      {'type': "url", 'url': "https://www.dronerc.it/shop_testbr/Core/upload.php"},
      {'type': "url", 'url': "https://www.dronerc.it/shop_testbr/upload/upload.php"},
      {'type': "url", 'url': "https://www.edujikim.com/intro/blue/insert.asp"},
      {'type': "url", 'url': "https://www.fabioluciani.com/es/include/include.asp"},
      {'type': "url", 'url': "http://trophylab.com/notice/images/renewal/upload.asp"},
      {'type': "url", 'url': "http://www.colasprint.com/_vti_log/upload.asp"},
      {'type': "domain", 'id': "angeldonationblog.com"},
      {'type': "domain", 'id': "codevexillium.org"},
      {'type': "domain", 'id': "investbooking.de"},
      {'type': "domain", 'id': "krakenfolio.com"},
      {'type': "domain", 'id': "opsonew3org.sg"},
      {'type': "domain", 'id': "transferwiser.io"},
      {'type': "domain", 'id': "transplugin.io"},
      {'type': "domain", 'id': "trophylab.com"},
      {'type': "domain", 'id': "www.colasprint.com"},
      {'type': "domain", 'id': "www.dronerc.it"},
      {'type': "domain", 'id': "www.edujikim.com"},
      {'type': "domain", 'id': "www.fabioluciani.com"}
  ]

  # Create Reference
  create_reference(
      url=url,
      creation_date="2021-01-25 00:00:00",
      title="New campaign targeting security researchers",
      author="Google Threat Analysis Group",
      iocs=iocs,
      client=client
  )

  client.close()

if __name__ == "__main__":
  main()
