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

import bz2
import datetime
import io
import json

import pytest
import pytest_httpserver

from vt import Client
from vt import FeedType
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

  with pytest.raises(ValueError, match=r'Object attributes must be a dictionary'):
    Object.from_dict({'type': 'dummy_type', 'id': 'dummy_id', 'attributes': 1})


def test_object_date_attrs():

  obj = Object('dummy_type')
  obj.foo_date = 0

  assert obj.foo_date == datetime.datetime(1970, 1, 1, 0, 0, 0)


def test_object_modified_attrs():

  obj = Object.from_dict({
      'type': 'dummy_type',
      'id': 'dummy_id',
      'attributes': {
          'attr1': 'foo',
          'attr2': 1,
          'attr3': {
              'subattr1': 'bar'
          },
          'attr4': {
              'subattr1': 'baz'
          }
      }})

  # No changes, attributes shouldn't appear in the dictionary.
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert 'attributes' not in obj_dict

  # attr1 set to its previous value, no changes yet.
  obj.attr1 = 'foo'
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert 'attributes' not in obj_dict

  # attr1 changed to 'bar', this should be the only attribute in the dictionary.
  obj.attr1 = 'bar'
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert len(obj_dict['attributes']) == 1
  assert obj_dict['attributes']['attr1'] == 'bar'

  obj.attr3['subattr1'] = 'foo'
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert len(obj_dict['attributes']) == 2
  assert obj_dict['attributes']['attr1'] == 'bar'
  assert obj_dict['attributes']['attr3'] == {'subattr1': 'foo'}

  del obj.attr4['subattr1']
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert len(obj_dict['attributes']) == 3
  assert obj_dict['attributes']['attr1'] == 'bar'
  assert obj_dict['attributes']['attr3'] == {'subattr1': 'foo'}
  assert obj_dict['attributes']['attr4'] == {}


def test_get(httpserver):

  httpserver.expect_request(
      '/api/v3/foo',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'data': 'dummy_data'
  })

  with new_client(httpserver) as client:
    response = client.get('/foo')

  assert response.status == 200


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

  assert obj.get('foo') == 'foo'
  assert obj.get('bar') == 'bar'
  assert obj.get('baz') is None

def test_patch_object(httpserver):

  obj = Object('dummy_type', 'dummy_id', {'foo': 1, 'bar': 2})
  obj.foo = 2

  httpserver.expect_request(
      '/api/v3/dummy_types/dummy_id',
      method='PATCH',
      headers={'X-Apikey': 'dummy_api_key'},
      data=json.dumps({'data': obj.to_dict(modified_attributes_only=True)}),
  ).respond_with_json({
      'data': {
          'id': 'dummy_id',
          'type': 'dummy_type',
          'attributes': {
              'foo': 2,
          }
      }
  })

  with new_client(httpserver) as client:
    client.patch_object('/dummy_types/dummy_id', obj=obj)


def test_post_object(httpserver):

  obj = Object('dummy_type')
  obj.foo = 'foo'

  httpserver.expect_request(
      '/api/v3/dummy_types',
      method='POST',
      headers={'X-Apikey': 'dummy_api_key'},
      data=json.dumps({'data': obj.to_dict()}),
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
    obj = client.post_object('/dummy_types', obj=obj)

  assert obj.id == 'dummy_id'


def test_delete(httpserver):

  httpserver.expect_request(
      '/api/v3/foo',
      method='DELETE',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'data': 'dummy_data'
  })

  with new_client(httpserver) as client:
    response = client.delete('/foo')

  assert response.status == 200


def test_iterator(httpserver):

  httpserver.expect_request(
      '/api/v3/dummy_collection/foo',
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
    it = client.iterator('/dummy_collection/foo', limit=10)
    for i, _ in enumerate(it):
      assert 0 == i


def test_download_file(httpserver):

  httpserver.expect_request(
      '/api/v3/files/01020304050607080900a0b0c0d0e0f/download',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_data('filecontent')

  with new_client(httpserver) as client:
    with io.BytesIO() as f:
      client.download_file('01020304050607080900a0b0c0d0e0f', f)
      f.seek(0)
      assert f.read() == b'filecontent'


def test_scan_file(httpserver):

  upload_url = (
      'http://' + httpserver.host + ':' + str(httpserver.port) + '/upload')

  httpserver.expect_oneshot_request(
      '/api/v3/files/upload_url',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'data': upload_url
  })

  httpserver.expect_oneshot_request(
      '/upload',
      method='POST',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'data': {
          'id': 'dummy_id',
          'type': 'analysis',
          'attributes': {
              'foo': 'foo',
          }
      }
  })

  with new_client(httpserver) as client:
    f = io.StringIO("dummy file")
    analysis = client.scan_file(f)

  assert analysis.type == 'analysis'


def test_scan_url(httpserver):

  httpserver.expect_request(
      '/api/v3/urls',
      method='POST',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'data': {
          'id': 'dummy_id',
          'type': 'analysis',
          'attributes': {
              'foo': 'foo',
          }
      }
  })

  with new_client(httpserver) as client:
    analysis = client.scan_url('https://www.dummy.url')

  assert analysis.type == 'analysis'


def test_feed(httpserver):

  httpserver.expect_ordered_request(
      '/api/v3/feeds/files/200102030405',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_data(
    bz2.compress(b'{\"type\": \"file\", \"id\": \"dummy_file_id_1\"}'))

  # The feed iterator should tolerate missing feed packages, so let's return
  # a NotFoundError for package 200102030406.
  httpserver.expect_ordered_request(
      '/api/v3/feeds/files/200102030406',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_json({
      'error': {
          'code': 'NotFoundError'
    }}, status=404)

  httpserver.expect_ordered_request(
      '/api/v3/feeds/files/200102030407',
      method='GET',
      headers={'X-Apikey': 'dummy_api_key'}
  ).respond_with_data(
    bz2.compress(b'{\"type\": \"file\", \"id\": \"dummy_file_id_2\"}'))

  with new_client(httpserver) as client:
    feed = client.feed(FeedType.FILES, cursor='200102030405')
    feed_iterator = feed.__iter__()
    obj = next(feed_iterator)
    assert obj.type == 'file'
    assert obj.id == 'dummy_file_id_1'
    obj = next(feed_iterator)
    assert obj.type == 'file'
    assert obj.id == 'dummy_file_id_2'
