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

"""Analyses URLs from a given file in VirusTotal."""

import argparse
import asyncio
import vt


async def get_urls_to_enqueue(queue, path, url):
  """Finds which URLs will be enqueued to scan in VirusTotal."""
  if url:
    await queue.put(url)
    return

  for u in path:
    await queue.put(u.strip())


async def enqueue_urls(queue, apikey):
  """Enqueues URLs in VirusTotal."""
  async with vt.Client(apikey) as client:
    while not queue.empty():
      url = await queue.get()
      await client.scan_url_async(url)
      print(f"URL {url} enqueued for scanning.")
      queue.task_done()


async def main():
  parser = argparse.ArgumentParser(description="Enqueue URLs to be scanned.")

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")
  parser.add_argument(
      "--workers",
      type=int,
      required=False,
      default=4,
      help="number of concurrent workers",
  )
  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument(
      "--path",
      type=argparse.FileType("r"),
      help="path to a file containing a list of URLs to scan.",
  )
  group.add_argument("--url", help="URL to scan.")
  args = parser.parse_args()

  queue = asyncio.Queue()
  asyncio.create_task(get_urls_to_enqueue(queue, args.path, args.url))

  worker_tasks = []
  for _ in range(args.workers):
    worker_tasks.append(asyncio.create_task(enqueue_urls(queue, args.apikey)))

  # Wait until all worker tasks has completed.
  await asyncio.gather(*worker_tasks)


if __name__ == "__main__":
  asyncio.run(main())
