#!/usr/local/bin/python
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

"""This example program shows how to use the vt-py asynchronous API for getting

the VirusTotal file feed in an efficient manner. This is a more elaborate
example than file_feed.py, it will run faster by leveraging the asynchronous
API for making concurrent calls to the VirusTotal backend.

NOTICE: In order to use this program you will need an API key that has
privileges for using the VirusTotal Feed API.
"""

import argparse
import asyncio
import json
import os
import signal
import vt


class FeedReader:
  """Reads and processes a VirusTotal file feed batch."""

  def __init__(
      self, apikey, output_dir, num_workers=4, download_files=False, cursor=None
  ):
    self._apikey = apikey
    self._aborted = False
    self._cursor = cursor
    self._output_dir = output_dir
    self._num_workers = num_workers
    self._download_files = download_files
    self._queue = asyncio.Queue(maxsize=num_workers)

  async def _get_from_feed_and_enqueue(self):
    """Get files from the file feed and put them into a queue."""
    async with vt.Client(self._apikey) as client:
      feed = client.feed(vt.FeedType.FILES, cursor=self._cursor)
      async for file_obj in feed:
        await self._queue.put(file_obj)
        if self._aborted:
          break
      self._cursor = feed.cursor

      self._enqueue_files_task.done()

  async def _process_files_from_queue(self):
    """Process files put in the queue by _get_from_feed_and_enqueue.

    This function runs in a loop until the feed reader is aborted, once aborted
    it keeps processing any file that remains in the queue.
    """
    async with vt.Client(self._apikey) as client:
      while not self._aborted or not self._queue.empty():
        file_obj = await self._queue.get()
        file_path = os.path.join(self._output_dir, file_obj.id)
        # Write a file <sha256>.json with file's metadata and another file
        # named <sha256> with the file's content.
        with open(file_path + ".json", mode="w", encoding="utf-8") as f:
          f.write(json.dumps(file_obj.to_dict()))
        if self._download_files:
          # The URL for downloading the file comes as a context attribute named
          # 'download_url'.
          download_url = file_obj.context_attributes["download_url"]
          response = await client.get_async(download_url)
          with open(file_path, mode="wb") as f:
            f.write(await response.read_async())
        else:
          # When not downloading files this yields the control to event loop
          # so that other coroutines haven an opportunity to run.
          await asyncio.sleep(0)
        self._queue.task_done()
        print(file_obj.id)

      task = self._worker_tasks.pop(0)
      task.done()

  def abort(self):
    self._aborted = True

  def cursor(self):
    return self._cursor

  def run(self):
    loop = asyncio.get_event_loop()
    loop_tasks = []
    # Create a task that read file object's from the feed and put them in a
    # queue.
    self._enqueue_files_task = loop.create_task(
        self._get_from_feed_and_enqueue()
    )
    loop_tasks.append(self._enqueue_files_task)

    # Create multiple tasks that read file object's from the queue, download
    # the file's content, and create the output files.
    self._worker_tasks = []
    for _ in range(self._num_workers):
      self._worker_tasks.append(
          loop.create_task(self._process_files_from_queue())
      )

    # If the program is interrupted, abort it gracefully.
    signals = (signal.SIGINT,)
    for s in signals:
      loop.add_signal_handler(s, self.abort)

    # Wait until all worker tasks has completed.
    loop_tasks.extend(self._worker_tasks)
    loop.run_until_complete(asyncio.gather(*loop_tasks))
    loop.close()


def main():
  parser = argparse.ArgumentParser(
      description=(
          "Get files from the VirusTotal feed. For each file in the feed a"
          " <sha256>.json file is created in the output directory containing"
          " information about the file. Additionally you can download the"
          " actual file with the --download-files option."
      )
  )

  parser.add_argument("--apikey", required=True, help="your VirusTotal API key")

  parser.add_argument(
      "--cursor", required=False, help="cursor indicating where to start"
  )

  parser.add_argument(
      "--output", default="./file-feed", help="path to output directory"
  )

  parser.add_argument(
      "--download-files", action="store_true", help="download files"
  )

  parser.add_argument(
      "--num_workers",
      type=int,
      required=False,
      help="number of concurrent workers",
      default=4,
  )

  args = parser.parse_args()

  if not os.path.exists(args.output):
    os.makedirs(args.output)

  feed_reader = FeedReader(
      args.apikey,
      args.output,
      num_workers=args.num_workers,
      download_files=args.download_files,
      cursor=args.cursor,
  )

  feed_reader.run()

  print(f"\ncontinuation cursor: {feed_reader.cursor()}")


if __name__ == "__main__":
  main()
