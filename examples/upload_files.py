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

"""Shows how to upload files to VT using vt-py."""

import argparse
import asyncio
import itertools
import os
import sys
import vt


async def get_files_to_upload(queue, path):
  """Finds which files will be uploaded to VirusTotal."""
  if os.path.isfile(path):
    await queue.put(path)
    return 1

  n_files = 0
  with os.scandir(path) as it:
    for entry in it:
      if not entry.name.startswith(".") and entry.is_file():
        await queue.put(entry.path)
        n_files += 1
  return n_files


async def upload_hashes(queue, apikey):
  """Uploads selected files to VirusTotal."""
  return_values = []

  async with vt.Client(apikey) as client:
    while not queue.empty():
      file_path = await queue.get()
      with open(file_path, encoding="utf-8") as f:
        analysis = await client.scan_file_async(file=f)
        print(f"File {file_path} uploaded.")
        queue.task_done()
        return_values.append((analysis, file_path))

  return return_values


async def process_analysis_results(apikey, analysis, file_path):
  async with vt.Client(apikey) as client:
    completed_analysis = await client.wait_for_analysis_completion(analysis)
    print(f"{file_path}: {completed_analysis.stats}")
    print(f"analysis id: {completed_analysis.id}")


async def main():
  parser = argparse.ArgumentParser(description="Upload files to VirusTotal.")

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")
  parser.add_argument(
      "--path", required=True, help="path to the file/directory to upload."
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
  n_files = await get_files_to_upload(queue, args.path)

  worker_tasks = []
  for _ in range(min(args.workers, n_files)):
    worker_tasks.append(asyncio.create_task(upload_hashes(queue, args.apikey)))

  # Wait until all worker tasks has completed.
  analyses = itertools.chain.from_iterable(await asyncio.gather(*worker_tasks))
  await asyncio.gather(
      *[
          asyncio.create_task(process_analysis_results(args.apikey, a, f))
          for a, f in analyses
      ]
  )


if __name__ == "__main__":
  asyncio.run(main())
