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

import aiohttp
import asyncio
import base64
import json
import io

from .error import APIError
from .feed import Feed
from .iterator import Iterator
from .object import Object
from .utils import make_sync
from .version import __version__


__all__ = [
    'Client',
    'ClientResponse',
    'url_id']


_API_HOST = 'https://www.virustotal.com'

# All API endpoints start with this prefix, you don't need to include the
# prefix in the paths you request as it's prepended automatically.
_ENDPOINT_PREFIX = '/api/v3'

# AppEngine server decides whether or not it should serve gzipped content
# based on Accept-Encoding and User-Agent. Non-standard UAs are not served
# with gzipped content unless it contains the string "gzip" somewhere.
# See: https://cloud.google.com/appengine/kb/#compression
_USER_AGENT_FMT = '{agent}; vtpy {version}; gzip'


def url_id(url):
  """Generates the object ID for an URL.

  The ID generated by this function can be used in calls that expect a URL ID
  like `client.get_object('/urls/<id>')`
  """
  return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


class ClientResponse:
  # pylint: disable=line-too-long
  """Class representing the HTTP responses returned by the client.

  This class is just a thing wrapper around `aiohttp.ClientResponse
  <https://aiohttp.readthedocs.io/en/stable/client_reference.html#aiohttp.ClientResponse>`_
  that allows using it in both asynchronous and synchronous mode. Instances of
  this class have all the attributes that you can find in `aiohttp.ClientResponse`,
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

  def __init__(self, aiohttp_resp):
    self._aiohttp_resp = aiohttp_resp

  def __getattr__(self, attr):
    return getattr(self._aiohttp_resp, attr)

  @property
  def content(self):
    return StreamReader(self._aiohttp_resp.content)

  async def _get_chunked_response(self):
    buffer = b''
    async for data, _ in self.content.iter_chunks():
      buffer += data
    return buffer

  async def read_async(self):
    if self.headers.get('Transfer-encoding') == 'chunked':
      return await self._get_chunked_response()
    else:
      return await self._aiohttp_resp.read()

  def read(self):
    return make_sync(self.read_async())

  async def json_async(self):
    if self.headers.get('Transfer-encoding') == 'chunked':
      response_content = await self._get_chunked_response()
      return json.loads(response_content)
    else:
      return await self._aiohttp_resp.json()

  def json(self):
    return make_sync(self.json_async())

  async def text_async(self):
    if self.headers.get('Transfer-encoding') == 'chunked':
      response_content = await self._get_chunked_response()
      return response_content.decode(self._aiohttp_resp.get_encoding())
    else:
      return await self._aiohttp_resp.text()

  def text(self):
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

  def __init__(self, aiohttp_stream_reader):
    self._aiohttp_stream_reader = aiohttp_stream_reader

  def __getattr__(self, attr):
    return getattr(self._aiohttp_stream_reader, attr)

  async def read_async(self, n=-1):
    return await self._aiohttp_stream_reader.read(n)

  def read(self, n=-1):
    return make_sync(self.read_async(n))

  async def readany_async(self):
    return await self._aiohttp_stream_reader.readany()

  def readany(self):
    return make_sync(self.readany_async())

  async def readexactly_async(self, n):
    return await self._aiohttp_stream_reader.readexactly(n)

  def readexactly(self, n):
    return make_sync(self.readexactly_async(n))

  async def readline_async(self):
    return await self._aiohttp_stream_reader.readline()

  def readline(self):
    return make_sync(self.readline_async())

  async def readchunk_async(self):
    return await self._aiohttp_stream_reader.readchunk()

  def readchunk(self):
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
  :type apikey: str
  :type agent: str
  :type host: str
  :type trust_env: bool
  :type timeout: int
  :type proxy: str
  :type headers: dict
  """

  def __init__(self, apikey, agent='unknown', host=None, trust_env=False,
               timeout=300, proxy=None, headers=None):
    """Initialize the client with the provided API key."""

    if not isinstance(apikey, str):
      raise ValueError('API key must be a string')

    if not apikey:
      raise ValueError('API key can not be an empty string')

    self._host = host or _API_HOST
    self._apikey = apikey
    self._agent = agent
    self._session = None
    self._trust_env = trust_env
    self._timeout = timeout
    self._proxy = proxy
    self._user_headers = headers

  def _full_url(self, path, *args):
    try:
      path = path.format(*args)
    except IndexError as exc:
      raise ValueError('Not enough arguments to fill all placeholders in path') from exc  # pylint: disable=line-too-long
    if path.startswith('http'):
      return path
    return self._host + _ENDPOINT_PREFIX + path

  def _get_session(self):
    if not self._session:
      headers = {
          'X-Apikey': self._apikey,
          'Accept-Encoding': 'gzip',
          'User-Agent': _USER_AGENT_FMT.format_map({
              'agent': self._agent, 'version': __version__})
      }

      if self._user_headers:
        headers.update(self._user_headers)

      self._session = aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False),
        headers=headers,
        trust_env=self._trust_env,
        timeout=aiohttp.ClientTimeout(total=self._timeout))
    return self._session

  async def __aenter__(self):
    return self

  async def __aexit__(self, type_, value, traceback):
    await self.close_async()

  def __enter__(self):
    return self

  def __exit__(self, type_, value, traceback):
    self.close()

  def _extract_data_from_json(self, json_response):
    if not 'data' in json_response:
      raise ValueError('response does not returns a data field')
    return json_response['data']

  async def _response_to_json(self, response):
    error = await self.get_error_async(response)
    if error:
      raise error
    return await response.json_async()

  async def _response_to_object(self, response):
    json_response = await self._response_to_json(response)
    try:
      return Object.from_dict(self._extract_data_from_json(json_response))
    except ValueError as err:
      raise ValueError(f'response is not an object: {err}') from err

  async def close_async(self):
    """Like :func:`close` but returns a coroutine."""
    if self._session:
      await self._session.close()
      self._session = None

  def close(self):
    """Closes the client.

    When the client is not needed anymore it should be closed for releasing
    resources like TCP connections.
    """
    return make_sync(self.close_async())

  def delete(self, path, *path_args):
    """Sends a DELETE request to a given API endpoint.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :type path: str
    :returns: An instance of :class:`ClientResponse`.
    """
    return make_sync(self.delete_async(path, *path_args))

  async def delete_async(self, path, *path_args):
    """Like :func:`delete` but returns a coroutine."""
    return ClientResponse(
        await self._get_session().delete(
          self._full_url(path, *path_args), proxy=self._proxy))

  def download_file(self, hash_, file):
    """Downloads a file given its _ (SHA-256, SHA-1 or MD5).

    The file identified by the hash will be written to the provided file
    object. The file object must be opened in write binary mode ('wb').

    :param hash_: File hash.
    :param file: A file object where the downloaded file will be written to.
    :type hash_: str
    :type file: file-like object
    """
    return make_sync(self.download_file_async(hash_, file))

  async def __download_async(self, endpoint, file):
    """Downloads a file and writes it to file.

    :param endpoint: endpoint to download the file from.
    :param file: A file object where the downloaded file will be written to.
    """
    response = await self.get_async(endpoint)
    error = await self.get_error_async(response)
    if error:
      raise error
    while True:
      chunk = await response.content.read_async(1024*1024)
      if not chunk:
        break
      file.write(chunk)

  async def download_file_async(self, hash_, file):
    """Like :func:`download_file` but returns a coroutine."""
    await self.__download_async(f'/files/{hash_}/download', file)

  def download_zip_files(self, hashes, zipfile, password=None, sleep_time=20):
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
        self.download_zip_files_async(hashes, zipfile, password, sleep_time))

  async def download_zip_files_async(
      self, hashes, zipfile, password=None, sleep_time=20):

    data = {'hashes': hashes}
    if password:
      data['password'] = password

    response = await self.post_async(
        '/intelligence/zip_files', data=json.dumps({'data': data}))
    error = await self.get_error_async(response)
    if error:
      raise error

    res_data = (await response.json_async())['data']

    # wait until the zip file is ready
    while res_data['attributes']['status'] in ('creating', 'starting'):
      await asyncio.sleep(sleep_time)
      response = await self.get_async(
          f'/intelligence/zip_files/{res_data["id"]}')
      error = await self.get_error_async(response)
      if error:
        raise error
      res_data = (await response.json_async())['data']

    # check for errors creating the zip file
    if res_data['attributes']['status'] != 'finished':
      raise APIError(
          'ServerError',
          f'Error when creating zip file: {res_data["attributes"]["status"]}')

    # download the zip file
    await self.__download_async(
        f'/intelligence/zip_files/{res_data["id"]}/download', zipfile)

  def feed(self, feed_type, cursor=None):
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

  def get(self, path, *path_args, params=None):
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

  async def get_async(self, path, *path_args, params=None):
    """Like :func:`get` but returns a coroutine."""
    return ClientResponse(
        await self._get_session().get(
            self._full_url(path, *path_args),
            params=params, proxy=self._proxy))

  def get_data(self, path, *path_args, params=None):
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

  async def get_data_async(self, path, *path_args, params=None):
    """Like :func:`get_data` but returns a coroutine."""
    json_response = await self.get_json_async(path, *path_args, params=params)
    return self._extract_data_from_json(json_response)

  async def get_error_async(self, response):
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
      if response.content_type == 'application/json':
        json_response = await response.json_async()
        error = json_response.get('error')
        if error:
          return APIError.from_dict(error)
      return APIError('ClientError', await response.text_async())
    return APIError('ServerError', await response.text_async())

  def get_json(self, path, *path_args, params=None):
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

  async def get_json_async(self, path, *path_args, params=None):
    """Like :func:`get_json` but returns a coroutine."""
    response = await self.get_async(path, *path_args, params=params)
    return await self._response_to_json(response)

  def get_object(self, path, *path_args, params=None):
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

  async def get_object_async(self, path, *path_args, params=None):
    """Like :func:`get_object` but returns a coroutine."""
    response = await self.get_async(path, *path_args, params=params)
    return await self._response_to_object(response)

  def patch(self, path, *path_args, data=None):
    """Sends a PATCH request to a given API endpoint.

    This is a low-level function that returns a raw HTTP response, no error
    checking nor response parsing is performed. See :func:`patch_object` for
    a higher-level function.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param data: Data sent in the request body.
    :type path: str
    :type data: A string or bytes
    :returns: An instance of :class:`ClientResponse`.
    """
    return make_sync(self.patch_async(path, *path_args, data))

  async def patch_async(self, path, *path_args, data=None):
    """Like :func:`patch` but returns a coroutine."""
    return ClientResponse(
        await self._get_session().patch(
            self._full_url(path, *path_args),
            data=data, proxy=self._proxy))

  def patch_object(self, path, *path_args, obj):
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

  async def patch_object_async(self, path, *path_args, obj):
    """Like :func:`patch_object` but returns a coroutine."""
    data = json.dumps({'data': obj.to_dict(modified_attributes_only=True)})
    response = await self.patch_async(path, *path_args, data=data)
    return await self._response_to_object(response)

  def post(self, path, *path_args, data=None):
    """Sends a POST request to a given API endpoint.

    This is a low-level function that returns a raw HTTP response, no error
    checking nor response parsing is performed. See :func:`post_object` for
    a higher-level function.

    :param path: Path to API endpoint, can contain format placeholders {}.
    :param path_args: A variable number of arguments that are put into any
      placeholders used in path.
    :param data: Data sent in the request body.
    :type path: str
    :type data: A string or bytes
    :returns: An instance of :class:`ClientResponse`.
    """
    return make_sync(self.post_async(path, *path_args, data=data))

  async def post_async(self, path, *path_args, data=None):
    """Like :func:`post` but returns a coroutine."""
    return ClientResponse(
        await self._get_session().post(
            self._full_url(path, *path_args),
            data=data, proxy=self._proxy))

  def post_object(self, path, *path_args, obj):
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

  async def post_object_async(self, path, *path_args, obj):
    """Like :func:`post_object` but returns a coroutine."""
    data = json.dumps({'data': obj.to_dict()})
    response = await self.post_async(path, *path_args, data=data)
    return await self._response_to_object(response)

  def iterator(self, path, *path_args, params=None, cursor=None,
               limit=None, batch_size=0):
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
    return Iterator(self, self._full_url(path, *path_args),
        params=params, cursor=cursor, limit=limit, batch_size=batch_size)

  def scan_file(self, file, wait_for_completion=False):
    """Scans a file.

    :param file: File to be scanned.
    :param wait_for_completion: If True the function doesn't return until the
       analysis has been completed.
    :type file: File-like object.
    :type wait_for_completion: bool
    :returns: An instance of :class:`Object` of analysis type.
    """
    return make_sync(self.scan_file_async(
        file, wait_for_completion=wait_for_completion))

  async def scan_file_async(self, file, wait_for_completion=False):
    """Like :func:`scan_file` but returns a coroutine."""

    if not isinstance(file, io.IOBase):
      raise TypeError(f'Expected a file to be a file object, got {type(file)}')

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
    filename = file.name if hasattr(file, 'name') else 'unknown'
    disposition = f'form-data; name="file"; filename="{filename}"'
    part.headers['Content-Disposition'] = disposition
    form_data = aiohttp.MultipartWriter('form-data')
    form_data.append_payload(part)

    upload_url = await self.get_data_async('/files/upload_url')
    response = ClientResponse(
        await self._get_session().post(
          upload_url, data=form_data, proxy=self._proxy))

    analysis = await self._response_to_object(response)

    if wait_for_completion:
      analysis = await self._wait_for_analysis_completion(analysis)

    return analysis

  def scan_url(self, url, wait_for_completion=False):
    """Scans a URL.

    :param url: The URL to be scanned.
    :param wait_for_completion: If True the function doesn't return until the
       analysis has been completed.
    :type url: str
    :type wait_for_completion: bool
    :returns: An instance of :class:`Object` of analysis type.
    """
    return make_sync(self.scan_url_async(
        url, wait_for_completion=wait_for_completion))

  async def scan_url_async(self, url, wait_for_completion=False):
    """Like :func:`scan_url` but returns a coroutine."""
    form_data = aiohttp.FormData()
    form_data.add_field('url', url)

    response = ClientResponse(
        await self._get_session().post(
          self._full_url('/urls'), data=form_data, proxy=self._proxy))

    analysis = await self._response_to_object(response)

    if wait_for_completion:
      analysis = await self._wait_for_analysis_completion(analysis)

    return analysis

  async def _wait_for_analysis_completion(self, analysis):
    while True:
      analysis = await self.get_object_async('/analyses/{}', analysis.id)
      if analysis.status == 'completed':
        break
      await asyncio.sleep(20)
    return analysis
