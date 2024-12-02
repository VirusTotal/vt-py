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

"""Tests features defined at vt/feed.py."""

import bz2
from collections import abc

import pytest
from vt import APIError, Client, FeedType


def new_client(httpserver):
  return Client(
      "dummy_api_key",
      host="http://" + httpserver.host + ":" + str(httpserver.port),
  )


@pytest.fixture(name="feed_response")
def fixture_feed_response(httpserver):
  httpserver.expect_ordered_request(
      "/api/v3/feeds/files/200102030405",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_data(
      bz2.compress(
          b'{"type": "file", "id": "dummy_file_id_1"}\n'
          b'{"type": "file", "id": "dummy_file_id_2"}\n'
          b'{"type": "file", "id": "dummy_file_id_3"}'
      )
  )

  httpserver.expect_ordered_request(
      "/api/v3/feeds/files/200102030406",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_data(
      bz2.compress(b'{"type": "file", "id": "dummy_file_id_4"}')
  )


@pytest.fixture(name="feed_response_missing_packages")
def fixture_feed_response_missing_packages(httpserver):
  httpserver.expect_ordered_request(
      "/api/v3/feeds/files/200102030405",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_data(
      bz2.compress(b'{"type": "file", "id": "dummy_file_id_1"}')
  )

  httpserver.expect_ordered_request(
      "/api/v3/feeds/files/200102030406",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"error": {"code": "NotFoundError"}}, status=404)

  httpserver.expect_ordered_request(
      "/api/v3/feeds/files/200102030407",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"error": {"code": "NotFoundError"}}, status=404)

  httpserver.expect_ordered_request(
      "/api/v3/feeds/files/200102030408",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_data(
      bz2.compress(b'{"type": "file", "id": "dummy_file_id_2"}')
  )


def test_interface(httpserver):
  """Tests feed's interface. Checks if the object is an actual iterator."""
  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES)

  assert isinstance(feed, abc.Iterator)
  assert isinstance(feed, abc.AsyncIterator)


@pytest.mark.usefixtures("feed_response")
def test_next(httpserver):
  """Tests feed's next."""
  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor="200102030405")

    obj = next(feed)
    assert obj.type == "file"
    assert obj.id == "dummy_file_id_1"

    obj = next(feed)
    assert obj.type == "file"
    assert obj.id == "dummy_file_id_2"

    obj = next(feed)
    assert obj.type == "file"
    assert obj.id == "dummy_file_id_3"

    # Iteration must start right where the last 'next' left
    for obj in feed:
      assert obj.type == "file"
      assert obj.id == "dummy_file_id_4"
      assert feed._count == 4  # pylint: disable=protected-access
      break  # Exit loop as the feed iteration doesn't stop


@pytest.mark.asyncio
@pytest.mark.usefixtures("feed_response")
async def test_anext(httpserver):
  """Tests feed's async next."""
  async with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor="200102030405")
    obj = await feed.__anext__()  # pylint: disable=unnecessary-dunder-call
    assert obj.type == "file"
    assert obj.id == "dummy_file_id_1"

    obj = await feed.__anext__()  # pylint: disable=unnecessary-dunder-call
    assert obj.type == "file"
    assert obj.id == "dummy_file_id_2"

    obj = await feed.__anext__()  # pylint: disable=unnecessary-dunder-call
    assert obj.type == "file"
    assert obj.id == "dummy_file_id_3"

    # Iteration must start right where the last 'next' left
    async for obj in feed:
      assert obj.type == "file"
      assert obj.id == "dummy_file_id_4"
      assert feed._count == 4  # pylint: disable=protected-access
      break  # Exit loop as the feed iteration doesn't stop


@pytest.mark.parametrize("tolerance", [0, 1, 2])
@pytest.mark.usefixtures("feed_response_missing_packages")
def test_tolerance(httpserver, tolerance):
  """Tests feed's tolerance to missing packages."""

  missing_batches = 2  # Consecutive missing batches in fixture

  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor="200102030405")
    # pylint: disable=protected-access
    feed._missing_batches_tolerancy = tolerance

    obj = next(feed)
    assert obj.id == "dummy_file_id_1"

    # The number of exceptions raised must equal the number of missing batches
    # minus the tolerance
    for _ in range(missing_batches - tolerance):
      with pytest.raises(APIError) as e_info:
        obj = next(feed)
      assert e_info.value.args[0] == "NotFoundError"

    obj = next(feed)
    assert obj.id == "dummy_file_id_2"
    assert feed._count == 2  # pylint: disable=protected-access


@pytest.mark.parametrize(
    "test_iters, expected_cursor",
    [
        (1, "200102030405-1"),
        (2, "200102030405-2"),
        (3, "200102030405-3"),
        (4, "200102030406-1"),
    ],
)
@pytest.mark.usefixtures("feed_response")
def test_cursor(httpserver, test_iters, expected_cursor):
  """Tests feed's cursor."""
  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor="200102030405")

    for _ in range(test_iters):
      next(feed)

    assert feed.cursor == expected_cursor


@pytest.mark.parametrize(
    "cursor, expected_file_id",
    [
        ("200102030405-0", "dummy_file_id_1"),
        ("200102030405-1", "dummy_file_id_2"),
        ("200102030405-2", "dummy_file_id_3"),
        ("200102030405-3", "dummy_file_id_4"),
    ],
)
@pytest.mark.usefixtures("feed_response")
def test_skip(httpserver, cursor, expected_file_id):
  """Tests feed's skip, used to continue where a previous object left."""
  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor=cursor)
    obj = next(feed)
    assert obj.id == expected_file_id
