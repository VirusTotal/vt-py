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

"""How to update a collection in VirusTotal."""

import argparse
import io
from pprint import pprint
import vt


def update_collection(client, collection_id, file):
  """Update a VirusTotal collection.

  Args:
    client: VirusTotal client.
    collection_id: Collection's id.
    file: File containing the IOCs to add to the collection.

  Returns:
    The new collection object.
  """

  collection_obj = vt.Object("collection", obj_id=collection_id)
  collection_obj.set_data("raw_items", file.read())
  return client.patch_object(
      f"/collections/{collection_id}", obj=collection_obj
  )


def generate_ui_link(collection_id):
  return f"https://www.virustotal.com/gui/collection/{collection_id}"


def main():
  parser = argparse.ArgumentParser(
      description="Update a VirusTotal collection."
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")
  parser.add_argument("--id", required=True, help="collection's id")

  args = parser.parse_args()
  client = vt.Client(args.apikey)

  # Typical usage would be to update a collection from a text file with IOCs:
  # with open('iocs.txt') as f:
  #   collection_obj = update_collection(client, args.id, f)

  # Or using a string with the IOCs.
  iocs = io.StringIO("www.example.com\nhttps://www.hooli.com")
  collection_obj = update_collection(client, args.id, iocs)

  client.close()
  pprint(collection_obj.to_dict())

  print(f"Link:\n{generate_ui_link(collection_obj.id)}")


if __name__ == "__main__":
  main()
