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

import asks
import functools
import trio

from .object import Object
from .iterator import Iterator
from .version import __version__

__all__ = ['Client']


_API_HOST = 'https://www.virustotal.com'

# All API endpoints start with this prefix, you don't need to include the
# prefix in the paths you request as it's prepended automatically.
_ENDPOINT_PREFIX = '/api/v3'

# AppEngine server decides whether or not it should serve gzipped content
# based on Accept-Encoding and User-Agent. Non-standard UAs are not served
# with gzipped content unless it contains the string "gzip" somewhere.
# See: https://cloud.google.com/appengine/kb/#compression
_USER_AGENT_FMT = '{agent}; vtpy {version}; gzip'


class APIError(Exception):
  """Class that encapsules errors returned by the VirusTotal API."""

  @classmethod
  def from_dict(cls, dict_error):
    return cls(dict_error['code'], dict_error.get('message'))

  def __init__(self, code, message):
    self.code = code
    self.message = message


class Client:
  """Client for interacting with VirusTotal."""

  def __init__(self, apikey: str, agent: str="unknown",
               max_connections: int=50, host: str=None):
    """Intialize the client with the provided API key.

    Args:
      apikey: VirusTotal API used by the client for authenticating.
      agent: Optional string identifying your application. Using a agent string
          is highly recommendable, as it may help in debugging issues with your
          requests server-side.
      max_connections: Maximum number of concurrent connections that the client
          can stablish to the server at any time. Default: 50.
    """
    self._session = asks.Session(host or _API_HOST, connections=max_connections)
    self._session.endpoint = _ENDPOINT_PREFIX
    self._session.headers['Accept-Encoding'] = 'gzip'
    self._session.headers['X-Apikey'] = apikey
    self._session.headers['User-Agent'] = _USER_AGENT_FMT.format_map({
        'agent': agent, 'version': __version__})

  async def get_async(self, path: str, params: dict=None):
    """Sends a GET request to the given path.

    This is a low-level function that returns a raw HTTP response, no error
    checking nor response parsing is performed. See get_json_response_async,
    get_data_async and get_object_async for higher-level functions.
    """
    return await self._session.get(path=path, params=params)

  async def get_json_response_async(self, path: str, params: dict=None):
    """Sends a GET request to the given path and parses the response.

    Most VirusTotal API responses are JSON-encoded. This function parses the
    JSON, check for errors, and return the server response as a dictionary.
    """
    http_resp = await self.get_async(path, params=params)
    json_resp = http_resp.json()
    error = json_resp.get('error')
    if error:
      raise APIError.from_dict(error)
    return json_resp

  async def get_data_async(self, path: str, params: dict=None):
    """Sends a GET request to the given path and returns response's data.

    Most VirusTotal API responses are JSON-encoded with the following format:

      {
        "data": <response data>
      }

    This function parses the server's response and return only the data, if the
    response is not in the expected format an exception is raised. For endpoints
    where the data is a VirusTotal object you can use get_object_async instead.

    Args:
      path: A path to the VirusTotal API.

    Returns:
      Whatever the server returned in the response's data field, it may be a
      dict, list, string or other Python type, depending on the endpoint called.
    """
    json_resp = await self.get_json_response_async(path, params=params)
    if not 'data' in json_resp:
      raise ValueError('{} does not returns a data field'.format(path))
    return json_resp['data']

  async def get_object_async(self, path: str, params: dict=None):
    """Send a GET request to the given path and return an object.

    The endpoint specified by path must return an object, not a collection. This
    means that get_object_async can be used with endpoints like /files/{file_id}
    and /urls/{url_id}, which return an individual object but not with /comments,
    which returns a collection of objects.
    """
    try:
      return Object.from_dict(await self.get_data_async(path, params=params))
    except ValueError as err:
      raise ValueError(
          '{} did not return an object: {}'.format(path, err))

  def get(self, *args, **kwargs):
    return trio.run(self.get_async, *args, **kwargs)

  def get_json_response(self, *args, **kwargs):
    return trio.run(functools.partial(
        self.get_json_response_async, *args, **kwargs))

  def get_data(self, *args, **kwargs):
    return trio.run(functools.partial(
        self.get_data_async, *args, **kwargs))

  def get_object(self, *args, **kwargs):
    return trio.run(functools.partial(
        self.get_object_async, *args, **kwargs))

  def iterator(self, path: str, cursor: str=None,
               limit: int=None, batch_size: int=None):
    """Returns an iterator for the collection specified by the given path.

    The endpoint specified by path must return a collection of objects. An
    example of such an endpoint are /comments and /intelligence/search.

    Args:
      path: The path for an endpoint returning a collection.
      cursor: Cursor for resuming the iteration at the point it was left
          previously. A cursor can be obtained with Iterator.cursor(). This
         cursor is not the same one returned by the VirusTotal API.
      limit: Maximum number of objects that will be returned by the iterator.
         If a limit is not provided the iterator continues until it reaches the
         last object in the collection.
      batch_size: Maximum number objects retrieved on each call to the API. If
         not provided the server will decide how many objects to return.
    """
    return Iterator(self, path,
        cursor=cursor, limit=limit, batch_size=batch_size)
