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

program_description = '''
Download files from VirusTotal given a list of hashes.\n

The list of hashes is read from the INPUT file, one hash per line. If no INPUT
file is specified hashes are read from the standard input.
'''

async def read_hashes(queue, input_file):
  for file_hash in input_file:
    await queue.put(file_hash.strip('\n'))


async def download_files(queue, args):
  async with vt.Client(args.apikey) as client:
    while not queue.empty():
      file_hash = await queue.get()
      file_path = os.path.join(args.output, file_hash)
      with open(file_path, 'wb') as f:
        await client.download_file_async(file_hash, f)
      print(file_hash)
      queue.task_done()


def main():

  parser = argparse.ArgumentParser(
      description=program_description)

  parser.add_argument('--apikey',
      required=True,
      help='your VirusTotal API key')

  parser.add_argument('--input',
      help='path to a file containing the hashes')

  parser.add_argument('--output',
      default='./file-feed',
      help='path to output directory')

  parser.add_argument('--workers',
      type=int,
      required=False,
      default=4,
      help='number of concurrent workers')

  args = parser.parse_args()

  if not os.path.exists(args.output):
    os.makedirs(args.output)

  if args.input:
    input_file = open(args.input)
  else:
    input_file = sys.stdin

  loop = asyncio.get_event_loop()
  queue = asyncio.Queue(loop=loop)
  loop.create_task(read_hashes(queue, input_file))

  _worker_tasks = []
  for i in range(args.workers):
    _worker_tasks.append(
        loop.create_task(download_files(queue, args)))

  # Wait until all worker tasks has completed.
  loop.run_until_complete(asyncio.gather(*_worker_tasks))
  loop.close()


if __name__ == '__main__':
  main()
