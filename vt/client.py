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

"""Main object to interact with the VT API."""

import asyncio
import base64
import functools
import io
import json
import typing
import os
import aiofiles

import aiohttp

from .error import APIError
from .feed import Feed, FeedType
from .iterator import Iterator
from .object import Object
from .object import UserDictJsonEncoder
from .utils import make_sync
from .version import __version__


__all__ = ["Client", "ClientResponse", "url_id"]


_API_HOST = "https://www.virustotal.com"

# All API endpoints start with this prefix, you don't need to include the
# prefix in the paths you request as it's prepended automatically.
_ENDPOINT_PREFIX = "/api/v3"

# AppEngine server decides whether or not it should serve gzipped content
# based on Accept-Encoding and User-Agent. Non-standard UAs are not served
# with gzipped content unless it contains the string "gzip" somewhere.
# See: https://cloud.google.com/appengine/kb/#compression
_USER_AGENT_FMT = "{agent}; vtpy {version}; gzip"

# https://github.com/aio-libs/aiohttp/discussions/6044#discussioncomment-1432443
setattr(asyncio.sslproto._SSLProtocolTransport, "_start_tls_compatible", True)  # pylint: disable=protected-access


def url_id(url: str) -> str:
  """Generates the object ID for an URL.

  The ID generated by this function can be used in calls that expect a URL ID
  like `client.get_object('/urls/<id>')`
  """
  return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class ClientResponse:
  # pylint: disable=line-too-long
  """Class representing the HTTP responses returned by the client.

  This class is just a thing wrapper around `aiohttp.ClientResponse
  <https://aiohttp.readthedocs.io/en/stable/client_reference.html#aiohttp.ClientResponse>`_
  that allows using it in both asynchronous and synchronous mode. Instances of
  this class have all the attributes that you can find in
  `aiohttp.ClientResponse`,
  like `version`, `status`, `method`, `url`, and so on. Methods in
  `aiohttp.ClientResponse` that return a coroutine have two flavors in this
  class: synchronous and asynchronous. For example,
  `aiohttp.ClientResponse.read()` becomes `vt.ClientResponse.read_async()`,
  and `vt.ClientResponse.read()` is the synchronous version of
  `vt.ClientResponse.read_async()`. Find more information about attributes and
  methods in `aiohttp.ClientResponse` in:

  https://aiohttp.readthedocs.io/en/stable/client_reference.html#aiohttp.ClientResponse
  """
  # pylint: enable=line-too-long

  def __init__(self, aiohttp_resp: aiohttp.ClientResponse):
    self._aiohttp_resp = aiohttp_resp

  def __getattr__(self, attr: str) -> typing.Any:
    return getattr(self._aiohttp_resp, attr)

  @property
  def content(self) -> "StreamReader":
    return StreamReader(self._aiohttp_resp.content)

  async def _get_chunked_response(self) -> bytes:
    buffer = b""
    async for data, _ in self.content.iter_chunks():
      buffer += data
    return buffer

  async def read_async(self) -> bytes:
    if self.headers.get("Transfer-encoding") == "chunked":
      return await self._get_chunked_response()
    else:
      return await self._aiohttp_resp.read()

  def read(self) -> bytes:
    return make_sync(self.read_async())

  async def json_async(self) -> typing.Dict:
    if self.headers.get("Transfer-encoding") == "chunked":
      response_content = await self._get_chunked_response()
      return json.loads(response_content)
    else:
      return await self._aiohttp_resp.json()

  def json(self) -> typing.Dict:
    return make_sync(self.json_async())

  async def text_async(self) -> str:
    if self.headers.get("Transfer-encoding") == "chunked":
      response_content = await self._get_chunked_response()
      return response_content.decode(self._aiohttp_resp.get_encoding())
    else:
      return await self._aiohttp_resp.text()

  def text(self) -> str:
    return make_sync(self.text_async())


class StreamReader:
  """Class representing the HTTP responses returned by the client.

  This class is just a thing wrapper around `aiohttp.StreamReader
  <https://aiohttp.readthedocs.io/en/stable/streams.html#aiohttp.StreamReader>`_
  that allows using it in both asynchronous and synchronous mode. Instances of
  this class have all the methods that you can find in `aiohttp.StreamReader`,
  like `readany()`, `readany()`, etc. Methods in `aiohttp.StreamReader`
  come in two flavors in this class: synchronous and asynchronous. For example,
  `read()` and `read_async`, where `read` is the synchronous one and
  `read_async` is the asynchronous. Find more information about attributes
  and methods in `aiohttp.StreamReader` in:

  https://aiohttp.readthedocs.io/en/stable/streams.html#aiohttp.StreamReader
  """

  def __init__(self, aiohttp_stream_reader: aiohttp.StreamReader):
    self._aiohttp_stream_reader = aiohttp_stream_reader

  def __getattr__(self, attr: str) -> typing.Any:
    return getattr(self._aiohttp_stream_reader, attr)

  async def read_async(self, n: int = -1) -> bytes:
    return await self._aiohttp_stream_reader.read(n)

  def read(self, n: int = -1) -> bytes:
    return make_sync(self.read_async(n))

  async def readany_async(self) -> bytes:
    return await self._aiohttp_stream_reader.readany()

  def readany(self) -> str:
    return make_sync(self.readany_async())

  async def readexactly_async(self, n: int) -> bytes:
    return await self._aiohttp_stream_reader.readexactly(n)

  def readexactly(self, n: int) -> bytes:
    return make_sync(self.readexactly_async(n))

  async def readline_async(self) -> bytes:
    return await self._aiohttp_stream_reader.readline()

  def readline(self) -> bytes:
    return make_sync(self.readline_async())

  async def readchunk_async(self) -> typing.Tuple[bytes, bool]:
    return await self._aiohttp_stream_reader.readchunk()

  def readchunk(self) -> typing.Tuple[bytes, bool]:
    return make_sync(self.readchunk_async())


class Client:
  """Client for interacting with VirusTotal.

  :param apikey: Your VirusTotal API key.
  :param agent: A string that identifies your application.
  :param host: By default https://www.virustotal.com, it can be changed for
    testing purposes.
  :param trust_env: Get proxies information from HTTP_PROXY/HTTPS_PROXY
    environment variables if the parameter is True (False by default).
  :param timeout: A int that determines the number of seconds to wait for
    a request to timeout (300 by default).
  :param proxy: A string indicating the proxy to use for requests
    made by the client (None by default).
  :param headers: Dict of headers defined by the user.
  :param verify_ssl: Whether to verify the certificate in SSL connections.
  :param connector: (Optional) A custom aiohttp connector.
  :type apikey: str
  :type agent: str
  :type host: str
  :type trust_env: bool
  :type timeout: int
  :type proxy: str
  :type headers: dict
  :type verify_ssl: bool
  :type connector: aiohttp.BaseConnector
  """

  def __init__(
      self,
      apikey: str,
      agent: str = "unknown",
      host: typing.Optional[str] = None,
      trust_env: bool = False,
      timeout: int = 300,
      proxy: typing.Optional[str] = None,
      headers: typing.Optional[typing.Dict] = None,
      verify_ssl: bool = True,
      connector: aiohttp.BaseConnector = None
  ):
    """Initialize the client with the provided API key."""

    if not isinstance(apikey, str):
      raise ValueError("API key must be a string")

    if not apikey:
      raise ValueError("API key can not be an empty string")

    self._host = host or _API_HOST
    self._apikey = apikey
    self._agent = agent
    self._session = None
    self._trust_env = trust_env
    self._timeout = timeout
    self._proxy = proxy
    self._user_headers = headers
    self._verify_ssl = verify_ssl
    if connector is not None:
      self._connector = connector
    else:
      # the TCPConnector class expects to be instantiated inside a event loop.
      # If there is none, create one.
      try:
        event_loop = asyncio.get_event_loop()
      except RuntimeError:
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)

      self._connector = aiohttp.TCPConnector(
          ssl=self._verify_ssl, loop=event_loop
      )

  def _full_url(self, path:str, *args: typing.Any) -> str:
    try:
      path = path.format(*args)
    except IndexError as exc:
      raise ValueError(
          "Not enough arguments to fill all placeholders in path"
      ) from exc  # pylint: disable=line-too-long
    if path.startswith("http"):
      return path
    return self._host + _ENDPOINT_PREFIX + path

  def _get_session(self) -> aiohttp.ClientSession:
    if not self._session:
      headers = {
          "X-Apikey": self._apikey,
          "Accept-Encoding": "gzip",
          "User-Agent": _USER_AGENT_FMT.format_map(
              {"agent": self._agent, "version": __version__}
          ),
      }

      if self._user_headers:
        headers.update(self._user_headers)

      self._session = aiohttp.ClientSession(
          connector=self._connector,
          headers=headers,
          trust_env=self._trust_env,
          timeout=aiohttp.ClientTimeout(total=self._timeout),
          json_serialize=functools.partial(json.dumps, cls=UserDictJsonEncoder)
      )
    return self._session

  async def __aenter__(self):
    return self

  async def __aexit__(self, item_type, value, traceback):
    await self.close_async()

  def __enter__(self):
    return self

  def __exit__(self, item_type, value, traceback):
    self.close()

  def _extract_data_from_json(self, json_response: typing.Any) -> typing.Any:
    if not "data" in json_response:
      raise ValueError("response does not returns a data field")
    return json_response["data"]

  async def _response_to_json(self, response: ClientResponse) -> typing.Dict:
    error = await self.get_error_async(response)
    if error:
      raise error
    return await response.json_async()

  async def _response_to_object(self, response: ClientResponse) -> Object:
    json_response = await self._response_to_json(response)
    try:
      return Object.from_dict(self._extract_data_from_json(json_response))
    except ValueError as err:
      raise ValueError(f"response is not an object: {err}") from err

  async def close_async(self) -> None:
    """Like :func:`close` but returns a coroutine."""
    # Using getattr(self, '_session', None) instead of self._session because
    # close_async can be called from __del__ when the object is not yet
    # inialized and therefore the object doesn't have a _session. Calling
    # self._session in that case would raise AttributeError. See:
    # https://github.com/VirusTotal/vt-py/issues/125#issue-1449917146
    session = getattr(self, "_session", None)
    if session:
      await session.close()
      self._session = None

  def close(self) -> None:
    """Closes the client.

    When the client is not needed anymore it must be closed for releasing
    resources like TCP connections.

    Not closing the client after it's used might show error tracebacks
    indicating it was not properly closed.
    """
    return make_sync(self.close_async())

  def delete(
    self,
    path: str,
    *path_args: typing.Any,
    data: typing.Optional[typing.Union[str, bytes]] = None,
    json_data: typing.Optional[typing.Dict] = None
  ) -> ClientResponse:
    """Sends a DELETE request to a given API endpoint.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param data: Data sent in the request body.
    :param json_data: dict containing data to send in the request body as JSON.
    :type path: str
    :type data: A string or bytes
    :type json_data: dict
    :returns: An instance of :class:`ClientResponse`.
    """
    return make_sync(
        self.delete_async(path, *path_args, data=data, json_data=json_data)
    )

  async def delete_async(
      self,
      path: str,
      *path_args: typing.Any,
      data: typing.Optional[typing.Union[str, bytes]] = None,
      json_data: typing.Optional[typing.Dict] = None
  ) -> ClientResponse:
    """Like :func:`delete` but returns a coroutine."""
    return ClientResponse(
        await self._get_session().delete(
            self._full_url(path, *path_args),
            data=data,
            json=json_data,
            proxy=self._proxy
        )
    )

  def download_file(self, file_hash: str, file: typing.BinaryIO) -> None:
    """Downloads a file given its _ (SHA-256, SHA-1 or MD5).

    The file identified by the hash will be written to the provided file
    object. The file object must be opened in write binary mode ('wb').

    :param file_hash: File hash.
    :param file: A file object where the downloaded file will be written to.
    :type file_hash: str
    :type file: file-like object
    """
    return make_sync(self.download_file_async(file_hash, file))

  async def __download_async(
    self,
    endpoint: str,
    file: typing.BinaryIO
  ) -> None:
    """Downloads a file and writes it to file.

    :param endpoint: endpoint to download the file from.
    :param file: A file object where the downloaded file will be written to.
    """
    response = await self.get_async(endpoint)
    error = await self.get_error_async(response)
    if error:
      raise error
    while True:
      chunk = await response.content.read_async(1024 * 1024)
      if not chunk:
        break
      file.write(chunk)

  async def download_file_async(
    self,
    file_hash : str,
    file: typing.BinaryIO
  ) -> None:
    """Like :func:`download_file` but returns a coroutine."""
    await self.__download_async(f"/files/{file_hash}/download", file)

  def download_zip_files(
    self,
    hashes: typing.List[str],
    zipfile: typing.BinaryIO,
    password: typing.Optional[str] = None,
    sleep_time: int = 20
  ) -> None:
    """Creates a bundle zip bundle containing one or multiple files.

    The file identified by the hash will be written to the provided file
    object. The file object must be opened in write binary mode ('wb').

    :param hashes: list of file hashes (SHA-256, SHA-1 or MD5).
    :param zipfile: A file object where the downloaded zip file
      will be written to.
    :param password: optional, a password to protect the zip file.
    :param sleep_time: optional, seconds to sleep between each request.
    """
    return make_sync(
        self.download_zip_files_async(hashes, zipfile, password, sleep_time)
    )

  async def download_zip_files_async(
    self,
    hashes: typing.List[str],
    zipfile: typing.BinaryIO,
    password: typing.Optional[str] = None,
    sleep_time: int = 20
  ) -> None:
    data = {"hashes": hashes}
    if password:
      data["password"] = password

    response = await self.post_async(
        "/intelligence/zip_files", data=json.dumps({"data": data})
    )
    error = await self.get_error_async(response)
    if error:
      raise error

    res_data = (await response.json_async())["data"]

    # wait until the zip file is ready
    while res_data["attributes"]["status"] in ("creating", "starting"):
      await asyncio.sleep(sleep_time)
      response = await self.get_async(
          f'/intelligence/zip_files/{res_data["id"]}'
      )
      error = await self.get_error_async(response)
      if error:
        raise error
      res_data = (await response.json_async())["data"]

    # check for errors creating the zip file
    if res_data["attributes"]["status"] != "finished":
      raise APIError(
          "ServerError",
          f'Error when creating zip file: {res_data["attributes"]["status"]}',
      )

    # download the zip file
    await self.__download_async(
        f'/intelligence/zip_files/{res_data["id"]}/download', zipfile
    )

  def feed(
    self,
    feed_type: FeedType,
    cursor: typing.Optional[str] = None
  ) -> Feed:
    """Returns an iterator for a VirusTotal feed.

    This functions returns an iterator that allows to retrieve a continuous
    stream of files as they are scanned by VirusTotal. See the documentation
    for the :class:`Feed` class for more details.

    :param feed_type: One of the supported feed types enumerated in
      :class:`FeedType`.
    :param cursor: An optional cursor indicating where to start. This argument
      can be a string in the format 'YYYMMDDhhmm' indicating the date and time
      of the first package that will be retrieved.
    :type hash: :class:`vt.FeedType`
    :type cursor: str
    """
    return Feed(self, feed_type, cursor=cursor)

  def get(
    self,
    path: str,
    *path_args: typing.Any,
    params: typing.Optional[typing.Dict] = None
  ) -> ClientResponse:
    """Sends a GET request to a given API endpoint.

    This is a low-level function that returns a raw HTTP response, no error
    checking nor response parsing is performed. See :func:`get_json`,
    :func:`get_data` and :func:`get_object` for higher-level functions.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param params: Parameters sent in the request.
    :type path: str
    :type params: dict
    :returns: An instance of :class:`ClientResponse`.
    """
    return make_sync(self.get_async(path, *path_args, params=params))

  async def get_async(
    self,
    path: str,
    *path_args: typing.Any,
    params: typing.Optional[typing.Dict] = None
  ) -> ClientResponse:
    """Like :func:`get` but returns a coroutine."""
    return ClientResponse(
        await self._get_session().get(
            self._full_url(path, *path_args), params=params, proxy=self._proxy
        )
    )

  def get_data(
    self,
    path: str,
    *path_args: typing.Any,
    params: typing.Optional[typing.Dict] = None
  ) -> typing.Any:
    """Sends a GET request to a given API endpoint and returns response's data.

    Most VirusTotal API responses are JSON-encoded with the following format::

      {"data": <response data>}

    This function parses the server's response and return only the data, if the
    response is not in the expected format an exception is raised. For endpoints
    where the data is a VirusTotal object you can use :func:`get_object`
    instead.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param params: Parameters sent in the request.
    :type path: str
    :type params: dict
    :returns:
      Whatever the server returned in the response's data field, it may be a
      dict, list, string or some other Python type, depending on the endpoint
      called.
    """
    return make_sync(self.get_data_async(path, *path_args, params=params))

  async def get_data_async(
      self,
      path: str,
      *path_args: typing.Any,
      params: typing.Optional[typing.Dict] = None
    ) -> typing.Any:
    """Like :func:`get_data` but returns a coroutine."""
    json_response = await self.get_json_async(path, *path_args, params=params)
    return self._extract_data_from_json(json_response)

  async def get_error_async(
    self,
    response: ClientResponse
  ) -> typing.Optional[APIError]:
    """Given a :class:`ClientResponse` returns a :class:`APIError`

    This function checks if the response from the VirusTotal backend was an
    error and returns the appropriate :class:`APIError` or None if no error
    occurred.

    :param response: A :class:`ClientResponse` instance.
    :returns: An instance of :class:`APIError` or None.
    """
    if response.status == 200:
      return None
    if response.status >= 400 and response.status <= 499:
      if response.content_type == "application/json":
        json_response = await response.json_async()
        error = json_response.get("error")
        if error:
          return APIError.from_dict(error)
      return APIError("ClientError", await response.text_async())
    return APIError("ServerError", await response.text_async())

  def get_json(
    self,
    path: str ,
    *path_args: typing.Any,
    params: typing.Optional[typing.Dict] = None
  ) -> typing.Dict:
    """Sends a GET request to a given API endpoint and parses the response.

    Most VirusTotal API responses are JSON-encoded. This function parses the
    JSON, check for errors, and return the server response as a dictionary.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param params: Parameters sent in the request.
    :type path: str
    :type params: dict
    :returns:
      A dictionary with the backend's response.
    """
    return make_sync(self.get_json_async(path, *path_args, params=params))

  async def get_json_async(
    self,
    path: str,
    *path_args: typing.Any,
    params: typing.Optional[typing.Dict] = None
  ) -> typing.Dict:
    """Like :func:`get_json` but returns a coroutine."""
    response = await self.get_async(path, *path_args, params=params)
    return await self._response_to_json(response)

  def get_object(
    self,
    path: str,
    *path_args: typing.Any,
    params: typing.Optional[typing.Dict] = None
  ) -> Object:
    """Sends a GET request to a given API endpoint and returns an object.

    The endpoint specified must return an object, not a collection. This
    means that get_object can be used with endpoints like /files/{file_id}
    and /urls/{url_id}, which return an individual object but not with
    /comments, which returns a collection of objects.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param params: Parameters sent in the request.
    :type path: str
    :type params: dict
    :returns:
      An instance of :class:`Object`.
    """
    return make_sync(self.get_object_async(path, *path_args, params=params))

  async def get_object_async(
    self,
    path: str,
    *path_args: typing.Any,
    params: typing.Optional[typing.Dict] = None
  ) -> Object:
    """Like :func:`get_object` but returns a coroutine."""
    response = await self.get_async(path, *path_args, params=params)
    return await self._response_to_object(response)

  def patch(
    self,
    path: str,
    *path_args: typing.Any,
    data: typing.Optional[typing.Union[str, bytes]] = None,
    json_data: typing.Optional[typing.Dict] = None
  ) -> ClientResponse:
    """Sends a PATCH request to a given API endpoint.

    This is a low-level function that returns a raw HTTP response, no error
    checking nor response parsing is performed. See :func:`patch_object` for
    a higher-level function.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param data: Data sent in the request body.
    :param json_data: dict containing data to send in the request body as JSON.
    :type path: str
    :type data: A string or bytes
    :type json_data: dict
    :returns: An instance of :class:`ClientResponse`.
    """
    return make_sync(self.patch_async(path, *path_args, data, json_data))

  async def patch_async(
    self,
    path: str,
    *path_args: typing.Any,
    data: typing.Optional[typing.Union[str, bytes]] = None,
    json_data: typing.Optional[typing.Dict] = None
  ) -> ClientResponse:
    """Like :func:`patch` but returns a coroutine."""
    return ClientResponse(
        await self._get_session().patch(
            self._full_url(path, *path_args),
            data=data,
            json=json_data,
            proxy=self._proxy,
        )
    )

  def patch_object(
    self,
    path: str,
    *path_args: typing.Any,
    obj: Object
  ) -> Object:
    """Sends a PATCH request for modifying an object.

    This function modifies an object. The endpoint must be one that identifies
    an object, like /intelligence/hunting_rulesets/{id}.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param obj: Object that has been modified.
    :type path: str
    :type obj: :class:`Object`
    :returns: An instance of :class:`Object` representing the same object after
      the changes has been applied.
    """
    return make_sync(self.patch_object_async(path, *path_args, obj=obj))

  async def patch_object_async(
    self,
    path: str,
    *path_args: typing.Any,
    obj: Object
  ) -> Object:
    """Like :func:`patch_object` but returns a coroutine."""
    data = {"data": obj.to_dict(modified_attributes_only=True)}

    response = await self.patch_async(path, *path_args, json_data=data)
    return await self._response_to_object(response)

  def post(
    self,
    path: str,
    *path_args: typing.Any,
    data: typing.Optional[typing.Union[str, bytes]] = None,
    json_data: typing.Optional[typing.Dict] = None
  ) -> ClientResponse:
    """Sends a POST request to a given API endpoint.

    This is a low-level function that returns a raw HTTP response, no error
    checking nor response parsing is performed. See :func:`post_object` for
    a higher-level function.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param data: Data sent in the request body.
    :param json_data: dict containing data to send in the request body as JSON.
    :type path: str
    :type data: A string or bytes
    :type json_data: dict
    :returns: An instance of :class:`ClientResponse`.
    """
    return make_sync(
        self.post_async(path, *path_args, data=data, json_data=json_data)
    )

  async def post_async(
    self,
    path: str,
    *path_args: typing.Any,
    data: typing.Optional[typing.Union[str, bytes]] = None,
    json_data: typing.Optional[typing.Dict] = None
  ) -> ClientResponse:
    """Like :func:`post` but returns a coroutine."""
    return ClientResponse(
        await self._get_session().post(
            self._full_url(path, *path_args),
            data=data,
            json=json_data,
            proxy=self._proxy,
        )
    )

  def post_object(
    self,
    path: str,
    *path_args: typing.Any,
    obj: Object
  ) -> Object:
    """Sends a POST request for creating an object.

    This function create a new object. The endpoint must be one that identifies
    a collection, like /intelligence/hunting_rulesets.

    :param path: Path to API endpoint.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param obj: Instance :class:`Object` with the type expected by the API
      endpoint.
    :type path: str
    :type obj: :class:`Object`
    :returns: An instance of :class:`Object` representing the new object.
    """
    return make_sync(self.post_object_async(path, *path_args, obj=obj))

  async def post_object_async(
    self,
    path: str,
    *path_args: typing.Any,
    obj: Object
  ) -> Object:
    """Like :func:`post_object` but returns a coroutine."""
    data = {"data": obj.to_dict()}

    response = await self.post_async(path, *path_args, json_data=data)
    return await self._response_to_object(response)

  def iterator(
    self,
    path: str,
    *path_args: typing.Any,
    params: typing.Optional[typing.Dict] = None,
    cursor: typing.Optional[str] = None,
    limit: typing.Optional[int] = None,
    batch_size: int = 0
  ) -> Iterator:
    """Returns an iterator for the collection specified by the given path.

    The endpoint specified by path must return a collection of objects. An
    example of such an endpoint are /comments and /intelligence/search.

    :param path: Path to API endpoint returning a collection.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param params: Additional parameters passed to the endpoint.
    :param cursor: Cursor for resuming the iteration at the point it was left
      previously. A cursor can be obtained with Iterator.cursor(). This
      cursor is not the same one returned by the VirusTotal API.
    :param limit: Maximum number of objects that will be returned by the
      iterator. If a limit is not provided the iterator continues until it
      reaches the last object in the collection.
    :param batch_size: Maximum number of objects retrieved on each call to the
      endpoint. If not provided the server will decide how many objects to
      return.
    :type path: str
    :type params: dict
    :type cursor: str
    :type limit: int
    :type batch_size: int
    :returns: An instance of :class:`Iterator`.
    """
    return Iterator(
        self,
        self._full_url(path, *path_args),
        params=params,
        cursor=cursor,
        limit=limit,
        batch_size=batch_size,
    )

  def scan_file(
    self,
    file: typing.BinaryIO,
    wait_for_completion: bool = False
  ) -> Object:
    """Scans a file.

    :param file: File to be scanned.
    :param wait_for_completion: If True the function doesn't return until the
       analysis has been completed.
    :type file: File-like object.
    :type wait_for_completion: bool
    :returns: An instance of :class:`Object` of analysis type.
    """
    return make_sync(
        self.scan_file_async(file, wait_for_completion=wait_for_completion)
    )

  async def scan_file_async(
    self,
    file: typing.BinaryIO,
    wait_for_completion: bool = False
  ) -> Object:
    """Like :func:`scan_file` but returns a coroutine."""

    if not isinstance(file, io.IOBase):
      raise TypeError(f"Expected a file to be a file object, got {type(file)}")

    # The snippet below could be replaced with this simpler code:
    #
    # form_data = aiohttp.FormData()
    # form_data.add_field('file', file)
    #
    # However, aiohttp.FormData assumes that the server supports RFC 5987 and
    # send a Content-Disposition like:
    #
    # 'form-data; name="file"; filename="foobar"; filename*=UTF-8''foobar
    #
    # AppEngine's upload handler doesn't like the filename*=UTF-8''foobar field
    # and fails with this Content-Disposition header.

    part = aiohttp.get_payload(file)
    filename = file.name if hasattr(file, "name") else "unknown"
    disposition = f'form-data; name="file"; filename="{filename}"'
    part.headers["Content-Disposition"] = disposition
    form_data = aiohttp.MultipartWriter("form-data")
    form_data.append_payload(part)

    upload_url = await self.get_data_async("/files/upload_url")
    response = ClientResponse(
        await self._get_session().post(
            upload_url, data=form_data, proxy=self._proxy
        )
    )

    analysis = await self._response_to_object(response)

    if wait_for_completion:
      analysis = await self._wait_for_analysis_completion(analysis)

    return analysis

  def scan_url(self, url: str, wait_for_completion: bool = False) -> Object:
    """Scans a URL.

    :param url: The URL to be scanned.
    :param wait_for_completion: If True the function doesn't return until the
       analysis has been completed.
    :type url: str
    :type wait_for_completion: bool
    :returns: An instance of :class:`Object` of analysis type.
    """
    return make_sync(
        self.scan_url_async(url, wait_for_completion=wait_for_completion)
    )

  async def scan_url_async(
    self,
    url: str,
    wait_for_completion: bool = False
  ) -> Object:
    """Like :func:`scan_url` but returns a coroutine."""
    form_data = aiohttp.FormData()
    form_data.add_field("url", url)

    response = ClientResponse(
        await self._get_session().post(
            self._full_url("/urls"), data=form_data, proxy=self._proxy
        )
    )

    analysis = await self._response_to_object(response)

    if wait_for_completion:
      analysis = await self._wait_for_analysis_completion(analysis)

    return analysis

  async def _wait_for_analysis_completion(self, analysis: Object) -> Object:
    while True:
      analysis = await self.get_object_async("/analyses/{}", analysis.id)
      if analysis.status == "completed":
        break
      await asyncio.sleep(20)
    return analysis

  async def wait_for_analysis_completion(self, analysis: Object) -> Object:
    return await self._wait_for_analysis_completion(analysis)

  def scan_file_private(
      self, 
      file: typing.Union[typing.BinaryIO, str],
      code_insight: bool = False,
      wait_for_completion: bool = False
  ) -> Object:
      """Scan file privately with optional code insight analysis.
      
      Args:
          file: File to scan (path string or file object)
          code_insight: Enable code analysis features
          wait_for_completion: Wait for completion
          
      Returns:
          Object: Analysis object with scan results
      """
      return make_sync(
          self.scan_file_private_async(file, code_insight, wait_for_completion)
      )

  async def scan_file_private_async(
      self,
      file: typing.Union[typing.BinaryIO, str],
      code_insight: bool = False, 
      wait_for_completion: bool = False
  ) -> Object:
      """Async version of scan_file_private"""
      
      # Handle string path
      if isinstance(file, str):
          async with aiofiles.open(file, 'rb') as f:
              file_content = io.BytesIO(await f.read())
              file_content.name = os.path.basename(file)
              return await self.scan_file_private_async(
                  file_content,
                  code_insight=code_insight,
                  wait_for_completion=wait_for_completion
              )

      # Create form data
      form = aiohttp.FormData()
      form.add_field('file', file)
      form.add_field('private', '1')
      form.add_field('code_insight', '1' if code_insight else '0')

      # Get upload URL and submit file
      upload_url = await self.get_data_async("/files/upload_url")
      response = await self.post_async(upload_url, data=form)
      
      analysis = await self._response_to_object(response)

      if wait_for_completion:
          analysis = await self._wait_for_analysis_completion(analysis)
      
      return analysis