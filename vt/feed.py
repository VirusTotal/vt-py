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


from datetime import datetime
from datetime import timedelta

import enum
import io
import json
import time
import asyncio
import bz2

from .error import APIError
from .object import Object


__all__ = [
    'Feed',
    'FeedType']


class FeedType(enum.Enum):
  """Feed types."""
  FILES = 'files'
  URLS = 'urls'
  FILE_BEHAVIOURS = 'file-behaviours'


class Feed:
  """Feed represents a stream of objects received from VirusTotal in real-time.

  For more information about VirusTotal Feeds see:
  https://developers.virustotal.com/v3.0/reference#feeds

  In the example below the loop iterates forever, retrieving file objects as
  they are processed by VirusTotal. For a more elaborate example see the file
  examples/file_feed.py in this repository.

  >>> with vt.Client(<apikey>) as client:
  >>> for file_obj in client.feed(vt.FeedType.FILES):
  >>>   print(file_obj.id)

  Instances of this class are not created directly, you should use the
  :func:`vt.Client.feed` method instead.
  """

  def __init__(self, client, feed_type, cursor=None):
    """Initializes a Feed object.

    This function is not intended to be called directly. Client.feed() is
    the preferred way for creating a feed.
    """
    self._client = client
    self._type = feed_type
    self._batch = None
    self._count = 0

    # This class tolerates a given number of missing batches in the feed,
    # if self._missing_batches_tolerancy is set to 0, there's no tolerancy
    # for missing batches and even a single missing batch will cause an error.
    # However, missing batches can occur from time to time.
    self._missing_batches_tolerancy = 1

    if cursor:
      batch_time, _, batch_skip = cursor.partition('-')
      self._batch_time = datetime.strptime(batch_time, '%Y%m%d%H%M')
      self._batch_skip = int(batch_skip) if batch_skip else 0
    else:
      self._batch_time = datetime.utcnow() - timedelta(minutes=70)
      self._batch_skip = 0

    self._next_batch_time = self._batch_time

  async def _get_batch_async(self, batch_time):
    """"Retrieves a specific batch from the backend.

    There's one batch per minute, each identified by the date in YYYYMMDDhhmm
    format. The batch_time argument is a datetime object that is converted to
    this format, the seconds in the datetime are ignored.
    """
    while True:
      response = await self._client.get_async('/feeds/{}/{}'.format(
          self._type.value, batch_time.strftime('%Y%m%d%H%M')))
      error = await self._client.get_error_async(response)
      if not error:
        break
      if error.code == 'NotAvailableYet':
        await asyncio.sleep(60)
      else:
        raise error
    return io.BytesIO(bz2.decompress(await response.content.read_async()))

  def _get_batch(self, *args, **kwargs):
    return asyncio.get_event_loop().run_until_complete(
        self._get_batch_async(*args, **kwargs))

  async def _get_next_batch_async(self):
    """Retrieves the next batch from the feed.

    This function tolerates a certain number of missing batches. If some batch
    is missing the next one will be retrieved. If more than
    """
    missing_batches = 0
    while True:
      try:
        self._batch_time = self._next_batch_time
        self._next_batch_time += timedelta(seconds=60)
        self._batch = await self._get_batch_async(self._batch_time)
        self._batch_cursor = 0
        break
      except APIError as error:
        # The only acceptable error here is NotFoundError, if such an error
        # occurs we try to get the next batch.
        if error.code != 'NotFoundError':
          raise error
        missing_batches += 1
        if missing_batches > self._missing_batches_tolerancy:
          raise error

  def _get_next_batch(self):
    return asyncio.get_event_loop().run_until_complete(
        self._get_next_batch_async())

  def _skip(self, n):
    for _ in range(n):
      self._batch.readline()
      self._batch_cursor += 1

  def __iter__(self):
    while True:
      if self._batch:
        next_item = self._batch.readline()
      else:
        self._get_next_batch()
        self._skip(self._batch_skip)
        self._batch_skip = 0
        next_item = self._batch.readline()
      self._batch_cursor += 1
      self._count += 1

      if next_item:
        yield Object.from_dict(json.loads(next_item.decode('utf-8')))
      else:
        self._batch = None

  async def __aiter__(self):
    while True:
      if self._batch:
        next_item = self._batch.readline()
      else:
        await self._get_next_batch_async()
        self._skip(self._batch_skip)
        self._batch_skip = 0
        next_item = self._batch.readline()
      self._batch_cursor += 1
      self._count += 1

      if next_item:
        yield Object.from_dict(json.loads(next_item.decode('utf-8')))
      else:
        self._batch = None

  @property
  def cursor(self):
    """Returns a cursor indicating the last item retrieved from the feed.

    This cursor can be used for creating a new Feed object that continues where
    a previous one left.
    """
    return self._batch_time.strftime('%Y%m%d%H%M-') + str(self._batch_cursor)
