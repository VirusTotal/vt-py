# Copyright 2020 The vt-py authors. All Rights Reserved.
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

import bz2
from collections import abc

import pytest

from vt import APIError, Client, FeedType


def new_client(httpserver):
  return Client('dummy_api_key',
                host='http://' + httpserver.host + ':' + str(httpserver.port))


@pytest.fixture
def feed_response(httpserver):
  httpserver.expect_ordered_request(
      '/api/v3/feeds/files/200102030405',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_data(
      bz2.compress(b'{\"type\": \"file\", \"id\": \"dummy_file_id_1\"}\n'
                   b'{\"type\": \"file\", \"id\": \"dummy_file_id_2\"}\n'
                   b'{\"type\": \"file\", \"id\": \"dummy_file_id_3\"}'))

  httpserver.expect_ordered_request(
      '/api/v3/feeds/files/200102030406',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_data(
      bz2.compress(b'{\"type\": \"file\", \"id\": \"dummy_file_id_4\"}'))


@pytest.fixture
def feed_response_missing_package(httpserver):
  httpserver.expect_ordered_request(
      '/api/v3/feeds/files/200102030405',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'error': {
          'code': 'NotFoundError'}}, status=404)

  httpserver.expect_ordered_request(
      '/api/v3/feeds/files/200102030406',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_data(
      bz2.compress(b'{\"type\": \"file\", \"id\": \"dummy_file_id_4\"}'))


def test_interface(httpserver):
  """Tests feed's interface. Checks if the object is an actual iterator."""
  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES)

  assert isinstance(feed, abc.Iterator)
  assert isinstance(feed, abc.AsyncIterator)


def test_next(httpserver, feed_response):
  """Tests feed's next."""
  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor='200102030405')

    obj = next(feed)
    assert obj.type == 'file'
    assert obj.id == 'dummy_file_id_1'

    obj = next(feed)
    assert obj.type == 'file'
    assert obj.id == 'dummy_file_id_2'

    obj = next(feed)
    assert obj.type == 'file'
    assert obj.id == 'dummy_file_id_3'

    # Iteration must start right where the last 'next' left
    for obj in feed:
      assert obj.type == 'file'
      assert obj.id == 'dummy_file_id_4'
      assert feed._count == 4
      break  # Exit loop as the feed iteration doesn't stop


@pytest.mark.asyncio
async def test_anext(httpserver, feed_response):
  """Tests feed's async next."""
  async with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor='200102030405')
    obj = await feed.__anext__()
    assert obj.type == 'file'
    assert obj.id == 'dummy_file_id_1'

    obj = await feed.__anext__()
    assert obj.type == 'file'
    assert obj.id == 'dummy_file_id_2'

    obj = await feed.__anext__()
    assert obj.type == 'file'
    assert obj.id == 'dummy_file_id_3'

    # Iteration must start right where the last 'next' left
    async for obj in feed:
      assert obj.type == 'file'
      assert obj.id == 'dummy_file_id_4'
      assert feed._count == 4
      break  # Exit loop as the feed iteration doesn't stop


@pytest.mark.parametrize("test_tolerance", [0, 1, 2])
def test_tolerance(httpserver, feed_response_missing_package, test_tolerance):
  """Tests feed's tolerance to missing packages."""
  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor='200102030405')
    feed._missing_batches_tolerancy = test_tolerance

    if feed._missing_batches_tolerancy:
      obj = next(feed)
      assert obj.type == 'file'
      assert obj.id == 'dummy_file_id_4'
      assert feed._count == 1
    else:
      with pytest.raises(APIError) as e_info:
        obj = next(feed)
      assert e_info.value.args[0] == 'NotFoundError'


@pytest.mark.parametrize("test_iters, expected_cursor",
                         [(1, '200102030405-1'),
                          (2, '200102030405-2'),
                          (3, '200102030405-3'),
                          (4, '200102030406-1')])
def test_cursor(httpserver, feed_response, test_iters, expected_cursor):
  """Tests feed's cursor."""
  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor='200102030405')

    for _ in range(test_iters):
      next(feed)

    assert feed.cursor == expected_cursor


@pytest.mark.parametrize("test_cursor, expected_file_id",
                         [('200102030405-0', 'dummy_file_id_1'),
                          ('200102030405-1', 'dummy_file_id_2'),
                          ('200102030405-2', 'dummy_file_id_3'),
                          ('200102030405-3', 'dummy_file_id_4')])
def test_skip(httpserver, feed_response, test_cursor, expected_file_id):
  """Tests feed's skip, used to continue where a previous object left."""
  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor=test_cursor)
    obj = next(feed)
    assert obj.id == expected_file_id
