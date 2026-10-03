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

"""Client tests."""

import collections
import datetime
import io
import functools
import json
import pickle

import pytest
from vt import APIError
from vt import Client
from vt import Object

from tests import wsgi_app


def new_client(httpserver, unused_apikey=""):
  return Client(
      "dummy_api_key",
      host="http://" + httpserver.host + ":" + str(httpserver.port),
      timeout=500,
  )


def test_object_from_dict():
  obj = Object.from_dict(
      {
          "type": "dummy_type",
          "id": "dummy_id",
          "attributes": {
              "attr1": "foo",
              "attr2": 1,
          },
          "relationships": {
              "foos": {"data": [{"type": "foo", "id": "foo_id"}]}
          },
      }
  )

  assert obj.id == "dummy_id"
  assert obj.type == "dummy_type"
  assert obj.attr1 == "foo"
  assert obj.attr2 == 1
  assert obj.relationships["foos"]["data"][0]["id"] == "foo_id"

  with pytest.raises(ValueError, match=r"Expecting dictionary, got: int"):
    Object.from_dict(1)

  with pytest.raises(ValueError, match=r"Object type not found"):
    Object.from_dict({})

  with pytest.raises(ValueError, match=r"Object id not found"):
    Object.from_dict({"type": "dummy_type"})

  with pytest.raises(
      ValueError, match=r"Object attributes must be a dictionary"
  ):
    Object.from_dict({"type": "dummy_type", "id": "dummy_id", "attributes": 1})


def test_object_date_attrs():
  obj = Object("dummy_type")
  obj.foo_date = 0

  assert obj.foo_date == datetime.datetime(
      1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)


def test_object_pickle():
  obj = Object("dummy")
  obj.whatever = {"1": "2"}
  new = pickle.loads(pickle.dumps(obj))
  assert new.whatever == obj.whatever
  assert new.to_dict() == obj.to_dict()


def test_object_to_dict():
  obj = Object.from_dict(
      {
          "type": "dummy_type",
          "id": "dummy_id",
          "attributes": {
              "attr1": "foo",
              "attr2": 1,
              "attr3": {"subattr1": "bar"},
              "attr4": {"subattr1": "baz"},
          },
      }
  )

  obj_dict = obj.to_dict()
  assert not isinstance(obj_dict["attributes"]["attr3"], collections.UserDict)

  obj.set_data("data_key", {"some": "value"})

  # No changes, attributes shouldn't appear in the dictionary.
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert not obj_dict["attributes"]
  # The new data field should appear in the dictionary.
  assert obj_dict["data_key"] == {"some": "value"}

  # attr1 set to its previous value, no changes yet.
  obj.attr1 = "foo"
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert not obj_dict["attributes"]

  # attr1 changed to 'bar', this should be the only attribute in the dictionary.
  obj.attr1 = "bar"
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert len(obj_dict["attributes"]) == 1
  assert obj_dict["attributes"]["attr1"] == "bar"

  obj.attr3["subattr1"] = "foo"
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert len(obj_dict["attributes"]) == 2
  assert obj_dict["attributes"]["attr1"] == "bar"
  assert obj_dict["attributes"]["attr3"] == {"subattr1": "foo"}

  del obj.attr4["subattr1"]
  obj_dict = obj.to_dict(modified_attributes_only=True)
  assert len(obj_dict["attributes"]) == 3
  assert obj_dict["attributes"]["attr1"] == "bar"
  assert obj_dict["attributes"]["attr3"] == {"subattr1": "foo"}
  assert obj_dict["attributes"]["attr4"] == {}


def test_get(httpserver):
  httpserver.expect_request(
      "/api/v3/foo", method="GET", headers={"X-Apikey": "dummy_api_key"}
  ).respond_with_json({"data": "dummy_data"})

  with new_client(httpserver) as client:
    response = client.get("/foo")

  assert response.status == 200


def test_get_data(httpserver):
  httpserver.expect_request(
      "/api/v3/foo", method="GET", headers={"X-Apikey": "dummy_api_key"}
  ).respond_with_json({"data": "dummy_data"})

  with new_client(httpserver) as client:
    data = client.get_data("/foo")

  assert data == "dummy_data"


def test_get_object(httpserver):
  httpserver.expect_request(
      "/api/v3/dummy_types/dummy_id",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": {
              "id": "dummy_id",
              "type": "dummy_type",
              "attributes": {"foo": "foo", "bar": "bar"},
          }
      }
  )

  with new_client(httpserver) as client:
    obj = client.get_object("/dummy_types/dummy_id")

  assert obj.id == "dummy_id"
  assert obj.type == "dummy_type"
  assert obj.foo == "foo"
  assert obj.bar == "bar"

  assert obj.get("foo") == "foo"
  assert obj.get("bar") == "bar"
  assert obj.get("baz") is None


def test_patch_object(httpserver):
  obj = Object("dummy_type", "dummy_id", {"foo": 1, "bar": 2})
  obj._context_attributes = {"a": "b"}  # pylint: disable=protected-access
  obj.foo = 2

  httpserver.expect_request(
      "/api/v3/dummy_types/dummy_id",
      method="PATCH",
      headers={"X-Apikey": "dummy_api_key", "Content-Type": "application/json"},
      json={"data": obj.to_dict(modified_attributes_only=True)},
  ).respond_with_json(
      {
          "data": {
              "id": "dummy_id",
              "type": "dummy_type",
              "attributes": {
                  "foo": 2,
              },
              "context_attributes": {"a": "b"},
          }
      }
  )

  with new_client(httpserver) as client:
    client.patch_object("/dummy_types/dummy_id", obj=obj)


def test_post_object(httpserver):
  obj = Object("dummy_type")
  obj.foo = "foo"

  httpserver.expect_request(
      "/api/v3/dummy_types",
      method="POST",
      headers={"X-Apikey": "dummy_api_key", "Content-Type": "application/json"},
      json={"data": obj.to_dict()},
  ).respond_with_json(
      {
          "data": {
              "id": "dummy_id",
              "type": "dummy_type",
              "attributes": {
                  "foo": "foo",
              },
          }
      }
  )

  with new_client(httpserver) as client:
    obj = client.post_object("/dummy_types", obj=obj)

  assert obj.id == "dummy_id"


def test_delete(httpserver):
  httpserver.expect_request(
      "/api/v3/foo",
      method="DELETE",
      headers={"X-Apikey": "dummy_api_key"},
      json={"hello": "world"},
  ).respond_with_json({"data": "dummy_data"})

  with new_client(httpserver) as client:
    response = client.delete("/foo", json_data={"hello": "world"})

  assert response.status == 200


def test_iterator(httpserver):
  httpserver.expect_request(
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
              }
          ]
      }
  )

  with new_client(httpserver) as client:
    it = client.iterator("/dummy_collection/foo", limit=10)
    for i, _ in enumerate(it):
      assert 0 == i


def test_download_file(httpserver):
  httpserver.expect_request(
      "/api/v3/files/01020304050607080900a0b0c0d0e0f/download",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_data("filecontent")

  with new_client(httpserver) as client:
    with io.BytesIO() as f:
      client.download_file("01020304050607080900a0b0c0d0e0f", f)
      f.seek(0)
      assert f.read() == b"filecontent"


def test_download_file_with_error(httpserver):
  httpserver.expect_request(
      "/api/v3/files/01020304050607080900a0b0c0ddead/download",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_data(
      status=404,
      content_type="application/json",
      response_data=json.dumps(
          {"error": {"code": "NotFoundError", "message": "Resource not found."}}
      ),
  )

  with pytest.raises(APIError) as e_info:
    with new_client(httpserver) as client:
      with io.BytesIO() as f:
        client.download_file("01020304050607080900a0b0c0ddead", f)
  assert e_info.value.args[0] == "NotFoundError"
  assert e_info.value.args[1] == "Resource not found."


def test_error_with_retry_after_seconds(httpserver):
  httpserver.expect_request(
      "/api/v3/files/01020304050607080900a0b0c0ddead",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_data(
      status=429,
      headers={"Retry-After": "120"},
      content_type="application/json",
      response_data=json.dumps(
          {"error": {"code": "QuotaExceededError", "message": "Quota exceeded"}}
      ),
  )

  with pytest.raises(APIError) as e_info:
    with new_client(httpserver) as client:
      client.get_object("/files/01020304050607080900a0b0c0ddead")
  assert e_info.value.code == "QuotaExceededError"
  assert e_info.value.retry_after == 120


def test_error_with_retry_after_http_date(httpserver):
  retry_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
      minutes=10
  )
  httpserver.expect_request(
      "/api/v3/files/01020304050607080900a0b0c0ddead",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_data(
      status=429,
      headers={
          "Retry-After": retry_at.strftime("%a, %d %b %Y %H:%M:%S GMT")
      },
      content_type="application/json",
      response_data=json.dumps(
          {"error": {"code": "QuotaExceededError", "message": "Quota exceeded"}}
      ),
  )

  with pytest.raises(APIError) as e_info:
    with new_client(httpserver) as client:
      client.get_object("/files/01020304050607080900a0b0c0ddead")
  assert 590 <= e_info.value.retry_after <= 600


def test_error_without_retry_after(httpserver):
  httpserver.expect_request(
      "/api/v3/files/01020304050607080900a0b0c0ddead",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_data(
      status=404,
      content_type="application/json",
      response_data=json.dumps(
          {"error": {"code": "NotFoundError", "message": "Resource not found."}}
      ),
  )

  with pytest.raises(APIError) as e_info:
    with new_client(httpserver) as client:
      client.get_object("/files/01020304050607080900a0b0c0ddead")
  assert e_info.value.retry_after is None


def test_download_zip_file(httpserver):
  httpserver.expect_ordered_request(
      "/api/v3/intelligence/zip_files",
      method="POST",
      headers={"X-Apikey": "dummy_api_key"},
      data=json.dumps({"data": {"hashes": ["h1", "h2"], "password": "pass"}}),
  ).respond_with_json(
      {
          "data": {
              "id": "1234",
              "type": "zip_file",
              "attributes": {"status": "starting"},
          }
      }
  )

  httpserver.expect_ordered_request(
      "/api/v3/intelligence/zip_files/1234",
      method="GET",
      headers={"x-apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": {
              "id": "1234",
              "type": "zip_file",
              "attributes": {"status": "creating"},
          }
      }
  )

  httpserver.expect_ordered_request(
      "/api/v3/intelligence/zip_files/1234",
      method="GET",
      headers={"x-apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": {
              "id": "1234",
              "type": "zip_file",
              "attributes": {"status": "finished"},
          }
      }
  )

  httpserver.expect_ordered_request(
      "/api/v3/intelligence/zip_files/1234/download",
      method="GET",
      headers={"x-apikey": "dummy_api_key"},
  ).respond_with_data("filecontent")

  with new_client(httpserver) as client:
    with io.BytesIO() as f:
      client.download_zip_files(["h1", "h2"], f, "pass", 1)
      f.seek(0)
      assert f.read() == b"filecontent"


def test_download_zip_file_error_creating_file(httpserver):
  httpserver.expect_ordered_request(
      "/api/v3/intelligence/zip_files",
      method="POST",
      headers={"X-Apikey": "dummy_api_key"},
      data=json.dumps({"data": {"hashes": ["h1", "h2"], "password": "pass"}}),
  ).respond_with_json(
      {
          "data": {
              "id": "1234",
              "type": "zip_file",
              "attributes": {"status": "starting"},
          }
      }
  )

  httpserver.expect_ordered_request(
      "/api/v3/intelligence/zip_files/1234",
      method="GET",
      headers={"x-apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": {
              "id": "1234",
              "type": "zip_file",
              "attributes": {"status": "creating"},
          }
      }
  )

  httpserver.expect_ordered_request(
      "/api/v3/intelligence/zip_files/1234",
      method="GET",
      headers={"x-apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": {
              "id": "1234",
              "type": "zip_file",
              "attributes": {"status": "timeout"},
          }
      }
  )

  with new_client(httpserver) as client:
    with io.BytesIO() as f:
      with pytest.raises(APIError) as e_info:
        client.download_zip_files(["h1", "h2"], f, "pass", 1)
      assert e_info.value.args[0] == "ServerError"
      assert e_info.value.args[1] == "Error when creating zip file: timeout"


def test_scan_file(httpserver):
  upload_url = (
      "http://" + httpserver.host + ":" + str(httpserver.port) + "/upload"
  )

  httpserver.expect_oneshot_request(
      "/api/v3/files/upload_url",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"data": upload_url})

  httpserver.expect_oneshot_request(
      "/upload", method="POST", headers={"X-Apikey": "dummy_api_key"}
  ).respond_with_json(
      {
          "data": {
              "id": "dummy_id",
              "type": "analysis",
              "attributes": {
                  "foo": "foo",
              },
          }
      }
  )

  with new_client(httpserver) as client:
    f = io.StringIO("dummy file")
    analysis = client.scan_file(f)

  assert analysis.type == "analysis"


def test_scan_file_valueerror(httpserver):
  """Tests an exception is raised when calling scan_file using invalid args."""
  with new_client(httpserver) as client:
    with pytest.raises(TypeError):
      client.scan_file("/Users/test/path/to/file.txt")


@pytest.mark.parametrize('private', [True, False])
def test_scan_url(httpserver, private):
  httpserver.expect_request(
      f"/api/v3/{'private/' if private else ''}urls", method="POST",
      headers={"X-Apikey": "dummy_api_key"}
  ).respond_with_json(
      {
          "data": {
              "id": "dummy_id",
              "type": f"{'private_' if private else ''}analysis",
              "attributes": {
                  "foo": "foo",
              },
          }
      }
  )

  with new_client(httpserver) as client:
    if private:
      analysis = client.scan_url_private("https://www.dummy.url")
    else:
      analysis = client.scan_url("https://www.dummy.url")

  assert analysis.type == f"{'private_' if private else ''}analysis"


def test_user_headers(httpserver):
  user_headers = {"foo": "bar"}

  client = Client(
      "dummy_api_key",
      host="http://" + httpserver.host + ":" + str(httpserver.port),
      timeout=500,
      headers=user_headers,
  )

  headers = client._get_session().headers  # pylint: disable=protected-access

  assert "X-Apikey" in headers
  assert "Accept-Encoding" in headers
  assert "User-Agent" in headers
  assert "foo" in headers


def test_wsgi_app(httpserver, monkeypatch):
  app = wsgi_app.app
  app.config.update({"TESTING": True})
  client = app.test_client()
  expected_response = {
      "data": {
          "id": "google.com",
          "type": "domain",
          "attributes": {"foo": "foo"},
      }
  }

  httpserver.expect_request(
      "/api/v3/domains/google.com",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json(expected_response)
  monkeypatch.setattr(
      "tests.wsgi_app.vt.Client", functools.partial(new_client, httpserver)
  )
  response = client.get("/")
  assert response.status_code == 200
  assert response.json == expected_response


@pytest.fixture(name='private_scan')
def private_scan_mocks(httpserver):
  """Fixture for mocking private scan API calls."""
  upload_url = f"http://{httpserver.host}:{httpserver.port}/upload"

  # Mock private upload URL request
  httpserver.expect_request(
      "/api/v3/private/files/upload_url", method="GET"
  ).respond_with_json({"data": upload_url})

  # Mock file upload response
  httpserver.expect_request("/upload", method="POST").respond_with_json(
      {
          "data": {
              "id": "dummy_scan_id",
              "type": "private_analysis",
              "links": {"self": "dummy_link"},
              "attributes": {
                  "status": "queued",
              },
          }
      }
  )

  # Add mock for analysis status endpoint
  httpserver.expect_request(
      "/api/v3/private/analyses/dummy_scan_id", method="GET"
  ).respond_with_json(
      {
          "data": {
              "id": "dummy_scan_id",
              "type": "private_analysis",
              "links": {"self": "dummy_link"},
              "attributes": {
                  "status": "completed",
                  "stats": {"malicious": 0, "suspicious": 0},
              },
          }
      }
  )

  return upload_url


def verify_analysis(analysis, status="queued"):
  """Helper to verify analysis response."""
  assert analysis.id == "dummy_scan_id"
  assert analysis.type == "private_analysis"
  assert getattr(analysis, "status") == status


def test_scan_file_private(httpserver, private_scan):  # pylint: disable=unused-argument
  """Test synchronous private file scanning."""
  with new_client(httpserver) as client:
    with io.StringIO("test file content") as f:
      analysis = client.scan_file_private(f)
    verify_analysis(analysis)


@pytest.mark.asyncio
async def test_scan_file_private_async(httpserver, private_scan):  # pylint: disable=unused-argument
  """Test asynchronous private file scanning."""
  async with new_client(httpserver) as client:
    with io.StringIO("test file content") as f:
      analysis = await client.scan_file_private_async(
          f, wait_for_completion=True
      )
    verify_analysis(analysis, status="completed")


def _quota_error_body():
  return json.dumps(
      {"error": {"code": "QuotaExceededError", "message": "Quota exceeded"}}
  )


def test_429_is_not_retried(httpserver):
  httpserver.expect_request(
      "/api/v3/files/01020304050607080900a0b0c0ddead", method="GET"
  ).respond_with_data(
      status=429,
      headers={"Retry-After": "0"},
      content_type="application/json",
      response_data=_quota_error_body(),
  )

  with pytest.raises(APIError) as e_info:
    with new_client(httpserver) as client:
      client.get_object("/files/01020304050607080900a0b0c0ddead")

  assert e_info.value.code == "QuotaExceededError"
  assert len(httpserver.log) == 1


def test_429_blocks_the_endpoint_locally(httpserver):
  httpserver.expect_request(
      "/api/v3/files/01020304050607080900a0b0c0ddead", method="GET"
  ).respond_with_data(
      status=429,
      headers={"Retry-After": "3600"},
      content_type="application/json",
      response_data=_quota_error_body(),
  )
  httpserver.expect_request(
      "/api/v3/files/0a0b0c0d0e0f/download", method="GET"
  ).respond_with_data("content")

  with new_client(httpserver) as client:
    with pytest.raises(APIError) as e_info:
      client.get_object("/files/01020304050607080900a0b0c0ddead")
    assert e_info.value.retry_after == 3600
    assert len(httpserver.log) == 1

    # The same endpoint with another ID now fails without contacting the API.
    with pytest.raises(APIError) as e_info:
      client.get_object("/files/0a0b0c0d0e0f")
    assert e_info.value.code == "QuotaExceededError"
    assert 3590 <= e_info.value.retry_after <= 3600
    assert len(httpserver.log) == 1

    # Other endpoints are not affected.
    client.get("/files/0a0b0c0d0e0f/download")
    assert len(httpserver.log) == 2


def test_quota_429_without_retry_after_does_not_block(httpserver):
  httpserver.expect_request(
      "/api/v3/files/01020304050607080900a0b0c0ddead", method="GET"
  ).respond_with_data(
      status=429,
      content_type="application/json",
      response_data=_quota_error_body(),
  )

  with new_client(httpserver) as client:
    for _ in range(2):
      with pytest.raises(APIError):
        client.get_object("/files/01020304050607080900a0b0c0ddead")

  assert len(httpserver.log) == 2


def test_edge_429_without_retry_after_blocks_by_default(httpserver):
  httpserver.expect_request(
      "/api/v3/files/01020304050607080900a0b0c0ddead", method="GET"
  ).respond_with_data(
      status=429,
      content_type="text/html",
      response_data="<title>429</title>429 Too Many Requests",
  )

  with new_client(httpserver) as client:
    with pytest.raises(APIError):
      client.get_object("/files/01020304050607080900a0b0c0ddead")
    with pytest.raises(APIError) as e_info:
      client.get_object("/files/01020304050607080900a0b0c0ddead")
    assert e_info.value.code == "QuotaExceededError"
    assert 50 <= e_info.value.retry_after <= 60

  assert len(httpserver.log) == 1


def test_endpoint_block_expires(httpserver, monkeypatch):
  path = "/api/v3/files/01020304050607080900a0b0c0ddead"
  httpserver.expect_ordered_request(path, method="GET").respond_with_data(
      status=429,
      headers={"Retry-After": "120"},
      content_type="application/json",
      response_data=_quota_error_body(),
  )
  httpserver.expect_ordered_request(path, method="GET").respond_with_json({
      "data": {
          "id": "01020304050607080900a0b0c0ddead",
          "type": "file",
          "attributes": {},
      }
  })

  now = [1000.0]
  monkeypatch.setattr("vt.client.time.monotonic", lambda: now[0])

  with new_client(httpserver) as client:
    with pytest.raises(APIError):
      client.get_object("/files/01020304050607080900a0b0c0ddead")
    now[0] += 121
    obj = client.get_object("/files/01020304050607080900a0b0c0ddead")

  assert obj.id == "01020304050607080900a0b0c0ddead"
  assert len(httpserver.log) == 2


@pytest.mark.parametrize(
    "method, url, key",
    [
        ("get", "https://www.virustotal.com/api/v3/files/abc1", "GET /files/*"),
        (
            "GET",
            "https://www.virustotal.com/api/v3/files/abc1/download?x=1",
            "GET /files/*/download",
        ),
        (
            "GET",
            "https://www.virustotal.com/api/v3/domains/example.com",
            "GET /domains/*",
        ),
        (
            "POST",
            "https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs",
            "POST /intelligence/retrohunt_jobs",
        ),
        (
            "POST",
            "https://www.virustotal.com/api/v3/private/files/abc1/analyse",
            "POST /private/files/*/analyse",
        ),
    ],
)
def test_endpoint_key(method, url, key):
  # pylint: disable=import-outside-toplevel,protected-access
  from vt import client as client_module

  assert client_module._endpoint_key(method, url) == key
