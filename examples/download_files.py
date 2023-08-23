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

"""Download files from VirusTotal given a list of hashes."""

import argparse
import asyncio
import io
import os
import sys
import vt

program_description = """
Download files from VirusTotal given a list of hashes.\n

The list of hashes is read from the INPUT file, one hash per line. If no INPUT
file is specified hashes are read from the standard input.
"""


async def read_hashes(queue, input_file):
  for file_hash in input_file:
    await queue.put(file_hash.strip("\n"))


async def download_files(queue, args):
  async with vt.Client(args.apikey) as client:
    while not queue.empty():
      file_hash = await queue.get()
      file_path = os.path.join(args.output, file_hash)
      file_content = io.BytesIO()
      try:
        await client.download_file_async(file_hash, file_content)
        with open(file_path, "wb") as f:
          f.write(file_content.getbuffer())
      except vt.error.APIError as e:
        print(f"ERROR writing {file_hash}: {e}")
      finally:
        print(file_hash)
        queue.task_done()


async def main():
  parser = argparse.ArgumentParser(description=program_description)

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")

  parser.add_argument("--input", help="path to a file containing the hashes")

  parser.add_argument(
      "--output", default="./file-feed", help="path to output directory"
  )

  parser.add_argument(
      "--workers",
      type=int,
      required=False,
      default=4,
      help="number of concurrent workers",
  )

  args = parser.parse_args()

  if not os.path.exists(args.output):
    os.makedirs(args.output)

  if args.input:
    input_file = open(args.input, encoding="utf-8")  # pylint: disable=consider-using-with
  else:
    input_file = sys.stdin

  queue = asyncio.Queue()
  asyncio.create_task(read_hashes(queue, input_file))

  worker_tasks = []
  for _ in range(args.workers):
    worker_tasks.append(asyncio.create_task(download_files(queue, args)))

  # Wait until all worker tasks has completed.
  await asyncio.gather(*worker_tasks)
  if input_file != sys.stdin:
    input_file.close()


if __name__ == "__main__":
  asyncio.run(main())
