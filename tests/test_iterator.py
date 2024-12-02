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

"""Tests features defined in vt/iterator.py."""

from collections import abc
import json
import pytest
import vt


def new_client(httpserver):
  return vt.Client(
      "dummy_api_key",
      host="http://" + httpserver.host + ":" + str(httpserver.port),
  )


@pytest.fixture(name="iterator_response")
def fixture_iterator_response(httpserver):
  httpserver.expect_ordered_request(
      "/api/v3/dummy_collection/foo",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": [
              {
                  "id": "dummy_id_1",
                  "type": "dummy_type",
                  "attributes": {"order": 0},
              },
              {
                  "id": "dummy_id_2",
                  "type": "dummy_type",
                  "attributes": {"order": 0},
              },
              {
                  "id": "dummy_id_3",
                  "type": "dummy_type",
                  "attributes": {"order": 0},
              },
          ],
          "meta": {"cursor": "3", "total_hits": 200},
      }
  )
  httpserver.expect_ordered_request(
      "/api/v3/dummy_collection/foo",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": [
              {
                  "id": "dummy_id_4",
                  "type": "dummy_type",
                  "attributes": {"order": 0},
              },
              {
                  "id": "dummy_id_5",
                  "type": "dummy_type",
                  "error": {
                      "code": "NotFoundError",
                      "message": "item not found.",
                  },
              },
          ]
      }
  )


def test_interface(httpserver):
  """Tests iterator's interface. Checks if object is an actual iterator."""
  with new_client(httpserver) as client:
    it = client.iterator("/dummy_collection/foo")
    assert isinstance(it, abc.Iterator)
    assert isinstance(it, abc.AsyncIterator)


@pytest.mark.usefixtures("iterator_response")
def test_next(httpserver):
  """Tests iterator's next with a limit higher than the total of elements."""
  with new_client(httpserver) as client:
    it = client.iterator("/dummy_collection/foo", limit=10, batch_size=3)
    assert next(it).id == "dummy_id_1"
    assert next(it).id == "dummy_id_2"
    assert it._batch_cursor == 2  # pylint: disable=protected-access

    # iteration must start right where the next stayed
    last = None
    for i, obj in enumerate(it):
      assert obj.id == f"dummy_id_{i+3}"
      if obj.id == "dummy_id_5":
        assert obj.error["code"] == "NotFoundError"
      else:
        assert obj.order == 0
        assert obj.error is None
      last = obj

    assert last.id == "dummy_id_5"
    assert it._count == 5  # pylint: disable=protected-access
    assert it._batch_cursor == 2  # pylint: disable=protected-access

    with pytest.raises(StopIteration):
      # there shouldn't be more available elements after the for loop
      next(it)

    # trying to iterate over next element must not work
    for obj in it:
      pytest.fail("Iteration should already be finished")


@pytest.mark.usefixtures("iterator_response")
def test_next_limit(httpserver):
  """Tests iterator's next with a limit smaller than the total of elements."""
  with new_client(httpserver) as client:
    it = client.iterator("/dummy_collection/foo", limit=3)
    assert next(it).id == "dummy_id_1"
    assert next(it).id == "dummy_id_2"

    # iteration must start right where the next stayed
    last = None
    for i, obj in enumerate(it):
      assert obj.id == f"dummy_id_{i+3}"
      last = obj

    # last element must be the one marked by the limit
    assert last.id == "dummy_id_3"
    assert it._count == 3  # pylint: disable=protected-access

    with pytest.raises(StopIteration):
      # there shouldn't be more available elements after the for loop
      next(it)

    # trying to iterate over next elements must not work
    for obj in it:
      pytest.fail("Iteration should already be finished")


@pytest.mark.asyncio
@pytest.mark.usefixtures("iterator_response")
async def test_anext(httpserver):
  """Tests iterator's async next."""
  async with new_client(httpserver) as client:
    it = client.iterator("/dummy_collection/foo", limit=10, batch_size=3)

    assert (await it.meta_async) == {"total_hits": 200}
    # Accessing meta loads the first batch of items, nevertheless the cursor
    # should be None until we start iterating.
    assert it.cursor is None

    assert (await it.__anext__()).id == "dummy_id_1"  # pylint: disable=unnecessary-dunder-call
    assert it._batch_cursor == 1  # pylint: disable=protected-access
    assert it.cursor

    # iteration must start right where the next stayed
    last, i = None, 0
    async for obj in it:
      assert obj.id == f"dummy_id_{i+2}"
      last = obj
      i += 1

    assert last.id == "dummy_id_5"
    assert it._count == 5  # pylint: disable=protected-access
    assert it._batch_cursor == 2  # pylint: disable=protected-access

    with pytest.raises(StopAsyncIteration):
      # there shouldn't be more available elements after the for loop
      await it.__anext__()  # pylint: disable=unnecessary-dunder-call

    # trying to iterate over next element must not work
    async for obj in it:
      pytest.fail("Iteration should already be finished")


def test_apierror_iterator(httpserver):
  """Tests errors are handled gracefully when iterating over a collection."""
  expected_error = {
      "data": {"error": "InvalidArgumentError", "message": "Invalid args"}
  }

  httpserver.expect_request("/api/v3/dummy_collection/foo").respond_with_json(
      expected_error, status=400
  )

  result = []
  with new_client(httpserver) as client:
    it = client.iterator("/dummy_collection/foo", limit=10, batch_size=3)

    with pytest.raises(vt.APIError) as e:
      for i in it:
        result.append(i)

    assert e.value.code == "ClientError"
    assert json.loads(e.value.message)["data"] == expected_error["data"]
