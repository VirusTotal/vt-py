# Copyright 2019 The vt-py authors. All Rights Reserved.
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

import json
import pytest
import pytest_httpserver

from vt import Client
from vt import Object


def new_client(httpserver):
  return Client('dummy_api_key',
      host='http://' + httpserver.host + ':' + str(httpserver.port))


def test_object_from_dict():

  obj = Object.from_dict({
      'type': 'dummy_type',
      'id': 'dummy_id',
      'attributes': {
          'attr1': 'foo',
          'attr2': 1,
      }})

  assert obj.id == 'dummy_id'
  assert obj.type == 'dummy_type'
  assert obj.attr1 == 'foo'
  assert obj.attr2 == 1

  with pytest.raises(ValueError, match=r"Expecting dictionary, got: int"):
    Object.from_dict(1)

  with pytest.raises(ValueError, match=r"Object type not found"):
    Object.from_dict({})

  with pytest.raises(ValueError, match=r"Object id not found"):
    Object.from_dict({'type': 'dummy_type'})

  with pytest.raises(ValueError, match=r"Object attributes not found"):
    Object.from_dict({'type': 'dummy_type', 'id': 'dummy_id'})

  with pytest.raises(ValueError, match=r'Object attributes must be a dictionary'):
    Object.from_dict({'type': 'dummy_type', 'id': 'dummy_id', 'attributes': 1})


def test_get_data(httpserver):

  httpserver.expect_request(
      '/api/v3/foo',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'data': 'dummy_data'
  })

  with new_client(httpserver) as client:
    data = client.get_data('/foo')

  assert data == 'dummy_data'


def test_get_object(httpserver):

  httpserver.expect_request(
      '/api/v3/dummy_types/dummy_id',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'data': {
          'id': 'dummy_id',
          'type': 'dummy_type',
          'attributes': {
              'foo': 'foo',
              'bar': 'bar'}
  }})

  with new_client(httpserver) as client:
    obj = client.get_object('/dummy_types/dummy_id')

  assert obj.id == 'dummy_id'
  assert obj.type == 'dummy_type'
  assert obj.foo == 'foo'
  assert obj.bar == 'bar'


def test_patch_object(httpserver):

  httpserver.expect_oneshot_request(
      '/api/v3/dummy_types/dummy_id',
      method='PATCH',
      headers={'X-Apikey': 'dummy_api_key'},
      data='{"data": {"type": "dummy_type", "id": "dummy_id", "attributes": {"foo": "foo"}}}',
  ).respond_with_json({
      'data': {
          'id': 'dummy_id',
          'type': 'dummy_type',
          'attributes': {
              'foo': 'foo',
          }
      }
  })

  with new_client(httpserver) as client:
    obj = Object('dummy_type', 'dummy_id')
    obj.foo = 'foo'
    data = client.patch_object('/dummy_types/dummy_id', obj)


def test_iterator(httpserver):

  httpserver.expect_request(
      '/api/v3/dummy_collection',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'data': [{
          'id': 'dummy_id_1',
          'type': 'dummy_type',
          'attributes': {'order': 0}
          }]
  })

  with new_client(httpserver) as client:
    it = client.iterator('/dummy_collection')
    for i, obj in enumerate(it):
      print(obj.id)
      assert 0 == i
