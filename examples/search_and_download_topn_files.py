#!/usr/bin/python

"""
This example program shows how to download files from VirusTotal matching a
VirusTotal Intelligence search.

NOTICE: In order to use this program you will need an API key that has
privileges for using VirusTotal Intelligence and for downloading files.
"""


import argparse
import asyncio
import logging
import os
import sys
import time
import vt


LOCAL_STORE = 'intelligencefiles'
STOP_SIGNAL = '__STOP__'

LOGGING_LEVEL = logging.INFO  # Modify if you just want to focus on errors
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)


class DownloadTopNFilesHandler:
  """Handler for Downloading files from VT."""

  def __init__(self, apikey, num_files):
    self.apikey = apikey
    self.num_files = num_files
    self.queue = asyncio.Queue()

  async def download_files(self, download_path):
    """Download files in queue to the path referenced by `download_path`.

    Args:
      download_path: string representing the path where the files will be
      stored.
    """
    stop = False

    async with vt.Client(self.apikey) as client:
      while not stop:
        file_hash = await self.queue.get()
        if file_hash == STOP_SIGNAL:
          stop = True
          # For stopping the rest of the workers
          await self.queue.put(STOP_SIGNAL)
        else:
          file_path = os.path.join(download_path, file_hash)
          with open(file_path, 'wb') as f:
            await client.download_file_async(file_hash, f)
          self.queue.task_done()

  async def queue_file_hashes(self, search):
    """Retrieve files from VT and enqueue them for being downloaded.

    Args:
      search: VT intelligence search query.
    """
    async with vt.Client(self.apikey) as client:
      it = client.iterator(
        '/intelligence/search',
        params={'query': search}, limit=self.num_files)
      async for file_obj in it:
        await self.queue.put(file_obj.sha256)
      await self.queue.put(STOP_SIGNAL)

  @staticmethod
  def create_download_folder(path=None):
    """Create the folder where the downloaded files will be put."""
    local_path = path or LOCAL_STORE
    folder_name = time.strftime('%Y%m%dT%H%M%S')
    folder_path = os.path.join(local_path, folder_name)

    if not os.path.exists(local_path):
      os.mkdir(local_path)
    if not os.path.exists(folder_path):
      os.mkdir(folder_path)

    return folder_path


def main():
  """Download the top-n results of a given Intelligence search."""

  usage = 'usage: prog [options] <intelligence_query/local_file_with_hashes>'
  parser = argparse.ArgumentParser(
      usage=usage,
      description='Allows you to download the top-n files returned by a given'
      'VirusTotal Intelligence search. Example: '
      'python %prog type:"peexe" positives:5+ -n 10 --apikey=<your api key>')

  parser.add_argument(
      'query', type=str, nargs='+',
      help='a VirusTotal Intelligence search query.')

  parser.add_argument(
      '-n', '--numfiles', dest='numfiles', default=100,
      help='Number of files to download')

  parser.add_argument('--apikey', required=True, help='Your VirusTotal API key')

  parser.add_argument(
    '-p', '--path', required=False,
    help='The path where you want to put the files in')

  parser.add_argument(
      '-w', '--workers', dest='workers', default=4,
      help='Concurrent workers for downloading files')

  args = parser.parse_args()

  if not args.query:
    parser.error('No search query provided')

  if not args.apikey:
    parser.error('No API key provided')

  search = ' '.join(args.query)
  search = search.strip().strip('\'')
  storage_path = args.path
  numfiles = int(args.numfiles)
  workers = int(args.workers)
  api_key = args.apikey
  loop = asyncio.get_event_loop()
  handler = DownloadTopNFilesHandler(api_key, numfiles)

  logging.info('Starting VirusTotal Intelligence downloader')
  logging.info('* VirusTotal Intelligence search: %s', search)
  logging.info('* Number of files to download: %s', numfiles)

  files_path = handler.create_download_folder(storage_path)
  task = loop.create_task(handler.queue_file_hashes(search))
  tasks = [task]

  for i in range(workers):
    tasks.append(loop.create_task(handler.download_files(files_path)))

  loop.run_until_complete(asyncio.gather(*tasks))
  loop.close()


if __name__ == '__main__':
  main()