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

import argparse
import asyncio
import os
import sys
import vt


async def get_files_to_upload(queue, path):
  """Finds which files will be uploaded to VirusTotal."""
  if os.path.isfile(path):
    await queue.put(path)
    return

  with os.scandir(path) as it:
    for entry in it:
        if not entry.name.startswith('.') and entry.is_file():
            await queue.put(entry.path)


async def upload_hashes(queue, apikey):
  """Uploads selected files to VirusTotal."""
  async with vt.Client(apikey) as client:
    while not queue.empty():
      file_path = await queue.get()
      await client.scan_file_async(file=file_path)
      print(f'File {file_path} uploaded.')
      queue.task_done()


def main():

  parser = argparse.ArgumentParser(description='Upload files to VirusTotal.')

  parser.add_argument('--apikey', required=True, help='your VirusTotal API key')
  parser.add_argument('--path', required=True,
                      help='path to the file/directory to upload.')
  parser.add_argument('--workers', type=int, required=False, default=4,
                      help='number of concurrent workers')
  args = parser.parse_args()

  if not os.path.exists(args.path):
    print(f'ERROR: file {args.path} not found.')
    sys.exit(1)

  loop = asyncio.get_event_loop()
  queue = asyncio.Queue(loop=loop)
  loop.create_task(get_files_to_upload(queue, args.path))

  _worker_tasks = []
  for i in range(args.workers):
    _worker_tasks.append(
        loop.create_task(upload_hashes(queue, args.apikey)))

  # Wait until all worker tasks has completed.
  loop.run_until_complete(asyncio.gather(*_worker_tasks))
  loop.close()


if __name__ == '__main__':
  main()
