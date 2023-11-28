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

"""Import YARA rulesets to a VirusTotal account.

This script imports either a ruleset in a file or all ruleset files in a given
directory. These imported YARA rules can be used in VT Hunting.

Read more:
https://www.virustotal.com/gui/hunting-overview
https://docs.virustotal.com/reference/list-hunting-rulesets
https://docs.virustotal.com/docs/whats-vthunting
"""

import argparse
import asyncio
import os
import sys
import vt


async def get_rules_files(queue, path):
  """Finds which rules will be uploaded to VirusTotal."""
  if os.path.isfile(path):
    await queue.put(path)
    return

  with os.scandir(path) as it:
    for entry in it:
      if not entry.name.startswith(".") and entry.is_file():
        await queue.put(entry.path)


async def upload_rules(queue, apikey, enable):
  """Uploads selected files to VirusTotal."""
  async with vt.Client(apikey) as client:
    while not queue.empty():
      file_path = await queue.get()
      with open(file_path, encoding="utf-8") as f:
        ruleset = vt.Object(
            obj_type="hunting_ruleset",
            obj_attributes={
                "name": os.path.basename(file_path),
                "enabled": enable,
                "rules": f.read(),
            },
        )

      try:
        await client.post_object_async(
            path="/intelligence/hunting_rulesets", obj=ruleset
        )
        print(f"File {file_path} uploaded.")
      except vt.error.APIError as e:
        print(f"Error uploading {file_path}: {e}")

      queue.task_done()


async def main():
  parser = argparse.ArgumentParser(
      description="Import YARA rules to a VirusTotal account."
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")
  parser.add_argument(
      "--path", required=True, help="path to the file/directory to upload."
  )
  parser.add_argument(
      "--enable",
      action="store_true",
      help="Whether to enable the YARA rules or not.",
  )
  parser.add_argument(
      "--workers",
      type=int,
      required=False,
      default=4,
      help="number of concurrent workers",
  )
  args = parser.parse_args()

  if not os.path.exists(args.path):
    print(f"ERROR: file {args.path} not found.")
    sys.exit(1)

  queue = asyncio.Queue()
  asyncio.create_task(get_rules_files(queue, args.path))

  worker_tasks = []
  for _ in range(args.workers):
    worker_tasks.append(
        asyncio.create_task(upload_rules(queue, args.apikey, args.enable))
    )

  # Wait until all worker tasks has completed.
  await asyncio.gather(*worker_tasks)


if __name__ == "__main__":
  asyncio.run(main())
