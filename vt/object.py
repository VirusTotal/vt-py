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

import datetime
import functools
import re

__all__ = ['Object']


class WhistleBlowerDict(dict):
  """Helper class for detecting changes in a dictionary.

  This class wraps a standard Python dictionary and calls the provided callback
  whenever a change occurs in the dictionary.
  """
  def __init__(self, initial_dict, on_change_callback):
    self._on_change_callback = on_change_callback
    for k,v in initial_dict.items():
      if isinstance(v, dict):
        initial_dict[k] = WhistleBlowerDict(v, on_change_callback)
    super().__init__(initial_dict)

  def __setitem__(self, item, value):
    if isinstance(value, dict):
      value = WhistleBlowerDict(value, self._on_change_callback)
    self._on_change_callback()
    super().__setitem__(item, value)

  def __delitem__(self, item):
    self._on_change_callback()
    super().__delitem__(item)


class Object:
  """This class encapsulates any type of object in the VirusTotal API.

  Instances of this class are usually obtained from calls to
  :meth:`vt.Client.get_object`, however, you need to instantiante this class
  yourself for creating new objects that will be sent to the backend in a call
  to :meth:`vt.Client.post_object`.

  Learn more about objects in the VirusTotal API in:
  https://developers.virustotal.com/v3.0/reference#objects
  """

  # Attributes from all object types that match any of the following names
  # represent a date as a UNIX timestamp. These attributes are converted to a
  # Python datetime object transparently.

  DATE_ATTRIBUTES = (
    re.compile(r'^.+_date$'),
    re.compile(r'^date$'),
    re.compile(r'^last_login$'),
    re.compile(r'^user_since$'),
  )

  @classmethod
  def from_dict(cls, obj_dict):
    """Creates an object from its dictionary representation.

    The dictionary representation of a VirusTotal API object has the following
    structure::

      {
        "type": <object type>,
        "id": <object id>,
        "links": {
          "self": "https://www.virustotal.com/api/v3/<collection name>/<object id>"
        },
        "attributes": {
          ...
        }
      }

    At least `type` and `id` are required to be present in the dictionary, if
    not, an exception is raised.
    """
    if not isinstance(obj_dict, dict):
      raise ValueError(
          f'Expecting dictionary, got: {type(obj_dict).__name__}')

    for field in ('type', 'id'):
      if field not in obj_dict:
        raise ValueError(f'Object {field} not found')

    obj = cls(
        obj_dict.get('type'),
        obj_dict.get('id'),
        obj_dict.get('attributes'))

    if 'context_attributes' in obj_dict:
      obj._context_attributes = obj_dict['context_attributes']

    if 'relationships' in obj_dict:
      obj._relationships = obj_dict['relationships']

    return obj

  def __init__(self, obj_type, obj_id=None, obj_attributes=None):
    """Initializes a VirusTotal API object."""

    if not isinstance(obj_attributes, (dict, type(None))):
      raise ValueError('Object attributes must be a dictionary')

    self._type = obj_type
    self._id = obj_id

    # Initialize object attributes with the ones coming in the obj_attributes,
    # this way if obj_attributes contains {'foo': 'somevalue'} you can access
    # the attribute as obj.foo and it will return 'somevalue'.
    if obj_attributes:
      for attr, value in obj_attributes.items():
        setattr(self, attr, value)

    self._modified_attrs = []

  def __on_attr_change(self, attr):
    if hasattr(self, '_modified_attrs'):
      self._modified_attrs.append(attr)

  def __getattribute__(self, attr):
    value = super().__getattribute__(attr)
    for re in Object.DATE_ATTRIBUTES:
      if re.match(attr):
        value = datetime.datetime.utcfromtimestamp(value)
        break
    return value

  def __setattr__(self, attr, value):
    if isinstance(value, dict):
      value = WhistleBlowerDict(
          value, functools.partial(self.__on_attr_change, attr))
    elif isinstance(value, datetime.datetime):
      value = int(datetime.datetime.timestamp(value))
    if attr not in self.__dict__ or value != self.__dict__[attr]:
      self.__on_attr_change(attr)
    super().__setattr__(attr, value)

  def __repr__(self):
    return f'<vt.object.Object {str(self)}>'

  def __str__(self):
    return f'{self.type} {self.id}'

  @property
  def id(self):
    return self._id

  @property
  def type(self):
    return self._type

  @property
  def context_attributes(self):
    if hasattr(self, '_context_attributes'):
      return self._context_attributes
    return {}

  @property
  def relationships(self):
    if hasattr(self, '_relationships'):
      return self._relationships
    return {}

  def get(self, attr_name, default=None):
    """Returns an attribute by name.

    If the attribute is not present in the object, it returns None
    or the value specified in the "default" argument.

    :param attr_name: Name of the attribute.
    :param default: An optional value that will be returned if the
      attribute is not present in the object.
    :type attr_name: str
    """
    return self.__dict__.get(attr_name, default)

  def to_dict(self, modified_attributes_only=False):
    result = {'type': self._type}

    if self._id:
      result['id'] = self._id

    attributes = {}
    for name, value in self.__dict__.items():
      if not name.startswith('_'):
        if not modified_attributes_only or name in self._modified_attrs:
          attributes[name] = value

    if attributes:
      result['attributes'] = attributes

    if self.relationships:
      result['relationships'] = self.relationships

    if self.context_attributes:
      result['context_attributes'] = self.context_attributes

    return result
