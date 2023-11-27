#!/usr/local/bin/python
# Copyright © 2020 The vt-py authors. All Rights Reserved.
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

"""Get provenance info for a given file.

This includes information signature, data from VT monitor, data from trusted
partners and from NSLR. The file is not uploaded to VirusTotal.
"""

import argparse
import asyncio
import hashlib
import sys
import vt


async def get_provenance_info(apikey, file_hash):
  async with vt.Client(apikey) as client:
    file_obj = await client.get_object_async(f"/files/{file_hash}")

  return (
      getattr(file_obj, "monitor_info", None),
      getattr(file_obj, "nsrl_info", None),
      getattr(file_obj, "signature_info", None),
      getattr(file_obj, "tags", []),
      getattr(file_obj, "trusted_verdict", None),
  )


async def main():
  parser = argparse.ArgumentParser(
      description="Get provenance info for a given file."
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")
  parser.add_argument(
      "--path",
      required=True,
      type=argparse.FileType("rb"),
      help="path to the file check.",
  )
  args = parser.parse_args()

  file_hash = hashlib.sha256(args.path.read()).hexdigest()

  try:
    monitor, nslr, signature, tags, trusted = await get_provenance_info(
        args.apikey, file_hash
    )
  except vt.error.APIError as e:
    print(f"ERROR: {e}")
    sys.exit(1)

  if monitor:
    print(
        "Present in monitor collections "
        f"of {', '.join(monitor['organizations'])}"
    )

  if nslr:
    print(f'Present in these products: {", ".join(nslr["products"])}')

  if signature:
    print(f'{"Inv" if "invalid-signature" in tags else "V"}alid signature.')
    print(f'Product: {signature["product"]}.')
    print(f'Signers: {signature["signers"]}')

  if trusted:
    print(f'Trusted file by {trusted["organization"]}')


if __name__ == "__main__":
  loop = asyncio.get_event_loop()
  loop.run_until_complete(main())
  loop.close()
