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


from .object import Object
from .utils import make_sync

__all__ = ['Iterator']


class Iterator:
  """Iterator allows iterating over object collections.

  Some endpoints in the VirusTotal API represent a collection of objects, for
  example:

  `/files/{id}/comments <https://developers.virustotal.com/v3.0/reference#files-comments-get>`_

  `/intelligence/search <https://developers.virustotal.com/v3.0/reference#intelligence-search>`_

  These collections can be iterated using an instance of this class.

  Learn more about collections in the VirusTotal API in:
  https://developers.virustotal.com/v3.0/reference#collections

  The following example iterates over the most recent 200 comments, retrieving
  them in batches of 20:

  >>> client = vt.Client(<apikey>)
  >>> it = client.iterator('/comments', batch_size=20, limit=200)
  >>> for comment in it:
  >>>   print(comment.text)
  >>> print(it.cursor)

  When the iteration is done, it print the iterator's cursor. The cursor can be
  used for creating another iterator that continues at the point where the
  previous iterator left.

  The Iterator class also exposes an async iterator:

  >>>  # Define an async coroutine that iterates over the comments.
  >>>  async def print_comments():
  >>>    async for comment in client.iterator('/comments', limit=200):
  >>>      print(comment.id)
  >>>  # Run the print_comments coroutine using asyncio
  >>>  import asyncio
  >>>  asyncio.get_event_loop().run_until_complete(print_comments)
  """

  def __init__(self, client, path, params=None, cursor=None,
               limit=None, batch_size=0):
    """Initializes an iterator.

    This function is not intended to be called directly. Client.iterator() is
    the preferred way for creating an iteraror.
    """
    self._client = client
    self._path = path
    self._params = params or {}
    self._batch_size = batch_size
    self._limit = limit
    self._items = []
    self._count = 0
    self._server_cursor = None
    self._batch_cursor = 0
    self._meta = None

    if 'cursor' in self._params:
      raise ValueError('Do not pass "cursor" as a path param')

    if 'limit' in self._params:
      raise ValueError('Do not pass "limit" as a path param')

    if cursor:
      self._server_cursor, _, batch_cursor = cursor.rpartition('-')
      if not self._server_cursor:
        raise ValueError('invalid cursor')
      try:
        self._batch_cursor = int(batch_cursor)
      except ValueError:
        raise ValueError('invalid cursor')

  def _build_params(self):
    params = self._params.copy()
    if self._server_cursor:
      params['cursor'] = self._server_cursor
    if self._batch_size:
      params['limit'] = self._batch_size
    return params

  def _parse_response(self, json_resp, batch_cursor):
    if not isinstance(json_resp.get('data'), list):
      raise ValueError(f'{self._path} is not a collection')
    meta = json_resp.get('meta', {})
    items = json_resp['data'][batch_cursor:]
    return items, meta

  async def _get_batch_async(self, batch_cursor=0):
    json_resp = await self._client.get_json_async(
        self._path, params=self._build_params())
    return self._parse_response(json_resp, batch_cursor)

  def __iter__(self):
    return self

  def __aiter__(self):
    return self

  def __next__(self):
    try:
      return make_sync(self.__anext__())
    except StopAsyncIteration:
      raise StopIteration()

  async def __anext__(self):
    if self._limit and self._count == self._limit:
      raise StopAsyncIteration()
    if not self._items and (self.cursor or self._count == 0):
      self._items, self._meta = await self._get_batch_async()
      self._server_cursor = self._meta.pop('cursor', None)
      self._batch_cursor = 0
    if not self._items and not self._server_cursor:
      raise StopAsyncIteration()
    item = self._items.pop(0)
    self._count += 1
    self._batch_cursor += 1
    return Object.from_dict(item)

  @property
  def cursor(self):
    """Cursor indicating the last returned object.

    This cursor can be used for creating a new iterator that continues where
    the current one left.
    """
    if not self._server_cursor or not self._count:
      return None
    return self._server_cursor + '-' + str(self._batch_cursor)

  @property
  async def meta_async(self):
    """Meta information.

    The cursor is not included, as it's exposed as a property.
    """
    if self._meta is None:
      # Load the first batch of items in order to retrieve the meta info.
      self._items, self._meta = await self._get_batch_async()
      self._server_cursor = self._meta.pop('cursor', None)
      self._batch_cursor = 0
    return self._meta

  @property
  def meta(self):
    return make_sync(self.meta_async)
