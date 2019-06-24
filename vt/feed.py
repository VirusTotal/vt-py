#!/usr/local/bin/python
# -*- coding: utf-8 -*-
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

import io
import json
import time
import asyncio
import bz2

from .error import APIError
from .object import Object


__all__ = ['Feed']


class Feed:
  """Feed represents a stream of objects received from VirusTotal in real-time.

  This class allows you to get information about objects as they are processed
  by VirusTotal. Your API key must have special privileges for using the feed
  API. See: https://developers.virustotal.com/v3.0/reference#feeds

  Example:
    with vt.Client(<apikey>) as client:
      for file_obj in client.Feed(vt.FeedType.FILES):
        print(file_obj.id)

  In the example above the loop iterates forever, retrieving file objects as
  they are processed by VirusTotal. For a more elaborate example see the file
  examples/file_feed.py in this repository.
  """

  def __init__(self, client, feed_type, cursor: str=None):
    """Initializes a Feed object.

    This function is not intended to be called directly. Client.feed() is
    the preferred way for creating a feed.
    """
    self._client = client
    self._type = feed_type
    self._batch = None
    self._count = 0

    if cursor:
      batch_time, _, batch_skip = cursor.partition('-')
      self._batch_time = datetime.strptime(batch_time, '%Y%m%d%H%M')
      self._batch_skip = int(batch_skip) if batch_skip else 0
    else:
      self._batch_time = datetime.utcnow() - timedelta(minutes=10)
      self._batch_skip = 0

    self._next_batch_time = self._batch_time

  async def _get_batch_async(self, batch_time):
    while True:
      response = await self._client.get_async('/feeds/{}/{}'.format(
          self._type.value, batch_time.strftime('%Y%m%d%H%M')))
      error = await self._client.get_error(response)
      if not error:
        break
      if error.code == 'NotAvailableYet':
        await asyncio.sleep(60)
      else:
        raise error
    return io.BytesIO(bz2.decompress(await response.content.read()))

  def _get_batch(self, *args, **kwargs):
    return asyncio.get_event_loop().run_until_complete(
        self._get_batch_async(*args, **kwargs))

  def _skip(self, n):
    for _ in range(n):
      self._batch.readline()
      self._batch_cursor += 1

  def __iter__(self):
    return self

  async def __aiter__(self):
    return self

  def __next__(self):
    if self._batch:
      next_item = self._batch.readline()
    else:
      next_item = None
    if not next_item:
      self._batch_time = self._next_batch_time
      self._batch = self._get_batch(self._batch_time)
      self._batch_cursor = 0
      self._skip(self._batch_skip)
      self._batch_skip = 0
      self._next_batch_time += timedelta(seconds=60)
      next_item = self._batch.readline()
    self._batch_cursor += 1
    self._count += 1
    return Object.from_dict(json.loads(next_item))

  async def __anext__(self):
    if self._batch:
      next_item = self._batch.readline()
    else:
      next_item = None
    if not next_item:
      self._batch_time = self._next_batch_time
      self._batch = await self._get_batch_async(self._batch_time)
      self._batch_cursor = 0
      self._skip(self._batch_skip)
      self._batch_skip = 0
      self._next_batch_time += timedelta(seconds=60)
      next_item = self._batch.readline()
    self._batch_cursor += 1
    self._count += 1
    return Object.from_dict(json.loads(next_item))

  def cursor(self):
    """Returns a cursor indicating the last item retrievied from the feed.

    This cursor can be used for creating a new Feed object that continues where
    a previous one left.
    """
    return self._batch_time.strftime('%Y%m%d%H%M-') + str(self._batch_cursor)
