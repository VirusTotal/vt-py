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

"""How to generate a reference in VirusTotal and add IOCs to it.

NOTICE: In order to use this program you will need an API key that has
privileges for creating References.
"""

import argparse
import base64
from pprint import pprint
import vt


def create_reference(url, creation_date, title, author, client, iocs):
  """Creates a reference in VirusTotal.

  Args:
    url: Reference url.
    creation_date: Reference creation date (YY-MM-DD HH:mm:ss).
    title: Reference title.
    author: Author
    client: VirusTotal client.
    iocs: Dict with the different IOCs to add to the reference.

  Returns:
    The new reference object.
  """

  # Generate url identifier
  payload = {
      "attributes": {
          "url": url,
          "creation_date": creation_date,
          "title": title,
          "author": author,
      },
      "relationships": {},
      "type": "reference",
      "id": "",
  }

  # Add IOCs to Reference.
  add_iocs_to_reference_payload(iocs, payload)

  ref_url = base64.b64encode(url.encode()).decode().strip("=")

  # Reference endpoint accepts both reference id or url encoded in base64.
  response_get_reference = client.get(f"/references/{ref_url}")

  exists = response_get_reference.status == 200

  if exists:
    payload["id"] = response_get_reference.json()["data"]["id"]

  reference_obj = vt.Object.from_dict(payload)

  if exists:
    print(f"Patching reference {url}...")
    return client.patch_object(f"/references/{ref_url}", obj=reference_obj)
  else:
    print(f"Posting reference {url}...")
    return client.post_object("/references", obj=reference_obj)


def add_iocs_to_reference_payload(iocs, reference_payload):
  """Adds IOCs relationships to a given reference.

  Args:
    iocs: Dict with the different IOCs to add to the reference.
    reference_payload: Reference payload
  """
  for relationship_name in ["files", "domains", "urls", "ip_addresses"]:
    if relationship_name not in iocs:
      continue
    if relationship_name == "urls":
      descriptors = [{"type": "url", "url": u} for u in iocs["urls"]]
    else:
      type_name = (
          "ip_address"
          if relationship_name == "ip_addresses"
          else relationship_name[:-1]
      )
      descriptors = [
          {"type": type_name, "id": i} for i in iocs[relationship_name]
      ]

    reference_payload["relationships"][relationship_name] = {
        "data": descriptors
    }


def main():
  parser = argparse.ArgumentParser(
      description="Create references and add IOCs to them."
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")

  args = parser.parse_args()
  client = vt.Client(args.apikey)

  # Reference's URL.
  url = (
      "https://blog.google/threat-analysis-group/"
      "new-campaign-targeting-security-researchers/"
  )

  # Fill in the reference's IOCs
  # Allowed types: files, domains, urls, ip_addresses.
  iocs = {
      "files": [
          "4c3499f3cc4a4fdc7e67417e055891c78540282dccc57e37a01167dfe351b244",
          "68e6b9d71c727545095ea6376940027b61734af5c710b2985a628131e47c6af7",
          "25d8ae4678c37251e7ffbaeddc252ae2530ef23f66e4c856d98ef60f399fa3dc",
          "a75886b016d84c3eaacaf01a3c61e04953a7a3adf38acf77a4a2e3a8f544f855",
          "a4fb20b15efd72f983f0fb3325c0352d8a266a69bb5f6ca2eba0556c3e00bd15",
      ],
      "urls": [
          "https://angeldonationblog.com/image/upload/upload.php",
          "https://codevexillium.org/image/download/download.asp",
          "https://investbooking.de/upload/upload.asp",
          "https://transplugin.io/upload/upload.asp",
          "https://www.dronerc.it/forum/uploads/index.php",
          "https://www.dronerc.it/shop_testbr/Core/upload.php",
          "https://www.dronerc.it/shop_testbr/upload/upload.php",
          "https://www.edujikim.com/intro/blue/insert.asp",
          "https://www.fabioluciani.com/es/include/include.asp",
          "http://trophylab.com/notice/images/renewal/upload.asp",
          "http://www.colasprint.com/_vti_log/upload.asp",
      ],
      "domains": [
          "angeldonationblog.comcodevexillium.org",
          "investbooking.de",
          "krakenfolio.com",
          "opsonew3org.sg",
          "transferwiser.io",
          "transplugin.io",
          "trophylab.com",
          "www.colasprint.com",
          "www.dronerc.it",
          "www.edujikim.com",
          "www.fabioluciani.com",
      ],
      "ip_addresses": [
          "193.70.64.169",
      ],
  }

  # Create Reference
  reference_obj = create_reference(
      url=url,
      creation_date="2021-01-25 00:00:00",
      title="New campaign targeting security researchers",
      author="Google Threat Analysis Group",
      iocs=iocs,
      client=client,
  )

  client.close()
  if reference_obj:
    pprint(reference_obj.to_dict())


if __name__ == "__main__":
  main()
