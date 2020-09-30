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

import pytest
import pytest_httpserver

from vt import Client


def new_client(httpserver):
  return Client('dummy_api_key',
      host='http://' + httpserver.host + ':' + str(httpserver.port))


@pytest.fixture
def iterator_response(httpserver):
  httpserver.expect_request(
      '/api/v3/dummy_collection/foo',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'data': [{
          'id': 'dummy_id_1',
          'type': 'dummy_type',
          'attributes': {'order': 0}
          }, {
          'id': 'dummy_id_2',
          'type': 'dummy_type',
          'attributes': {'order': 0}
          }, {
          'id': 'dummy_id_3',
          'type': 'dummy_type',
          'attributes': {'order': 0}
          }, {
          'id': 'dummy_id_4',
          'type': 'dummy_type',
          'attributes': {'order': 0}
          }]
  })


def test_next(httpserver, iterator_response):
  """Tests iterator's next with a limit higher than the total of elements."""
  with new_client(httpserver) as client:
    it = client.iterator('/dummy_collection/foo', limit=10)
    assert next(it).id == 'dummy_id_1'
    assert next(it).id == 'dummy_id_2'

    # iteration must start right where the next stayed
    last = None
    for i, obj in enumerate(it):
      assert obj.id == f'dummy_id_{i+3}'
      last = obj

    assert last.id == 'dummy_id_4'
    assert it._count == 4

    with pytest.raises(StopIteration):
      # there shouldn't be more available elements after the for loop
      next(it)

    # trying to iterate over next element must not work
    for obj in it:
      pytest.fail('Iteration should already be finished')


def test_next_limit(httpserver, iterator_response):
  """Tests iterator's next with a limit smaller than the total of elements."""
  with new_client(httpserver) as client:
    it = client.iterator('/dummy_collection/foo', limit=3)
    assert next(it).id == 'dummy_id_1'
    assert next(it).id == 'dummy_id_2'

    # iteration must start right where the next stayed
    last = None
    for i, obj in enumerate(it):
      assert obj.id == f'dummy_id_{i+3}'
      last = obj

    # last element must be the one marked by the limit
    assert last.id == 'dummy_id_3'
    assert it._count == 3

    with pytest.raises(StopIteration):
      # there shouldn't be more available elements after the for loop
      next(it)

    # trying to iterate over next elements must not work
    for obj in it:
      pytest.fail('Iteration should already be finished')

@pytest.mark.asyncio
async def test_anext(httpserver, iterator_response):
  """Tests iterator's async next."""
  async with new_client(httpserver) as client:
    it = client.iterator('/dummy_collection/foo', limit=10)
    assert (await it.__anext__()).id == 'dummy_id_1'

    # iteration must start right where the next stayed
    last, i = None, 0
    async for obj in it:
      assert obj.id == f'dummy_id_{i+2}'
      last = obj
      i += 1

    assert last.id == 'dummy_id_4'
    assert it._count == 4

    with pytest.raises(StopAsyncIteration):
      # there shouldn't be more available elements after the for loop
      await it.__anext__()

    # trying to iterate over next element must not work
    async for obj in it:
      pytest.fail('Iteration should already be finished')
