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


__all__ = ['Object']

class Object:
  """Object describes any type of object returned by the VirusTotal API."""

  @classmethod
  def from_dict(cls, obj_dict: dict):
    """Creates an object from its dictionary representation.

    The dictionary representation of a VirusTotal API object has the following
    structure:

      {
        "type": <object type>,
        "id": <object id>,
        "links": {
          "self": "https://www.virustotal.com/api/v3/<collection name>/<object id>"
        },
        "attributes" : {
          ...
        }

    At least "type", "id" and "attributes" are required to be present in the
    dictionary, if not, an exception is raised.
    """
    if not isinstance(obj_dict, dict):
      raise ValueError(
          'Expecting dictionary, got: {}'.format(type(obj_dict).__name__))

    for field in ('type', 'id', 'attributes'):
      if field not in obj_dict:
        raise ValueError('Object {} not found'.format(field))

    return cls(
        obj_dict['type'],
        obj_dict['id'],
        obj_dict['attributes'],
        obj_dict.get('context_attributes'))

  def __init__(self, obj_type: str, obj_id: str,
               obj_attributes: dict, context_attributes: dict=None):
    """Initializes a VirusTotal API object."""

    if not isinstance(obj_attributes, dict):
      raise ValueError('Object attributes must be a dictionary')

    # Initialize object attributes with the ones coming in the obj_attributes,
    # this way if obj_attributes contains {'foo': 'somevalue'} you can access
    # the attribute as obj.foo and it will return 'somevalue'. This must be
    # done before initializing any other attribute for the object.
    self.__dict__ = obj_attributes

    self._type = obj_type
    self._id = obj_id
    self.context_attributes = context_attributes

  @property
  def id(self):
    return self._id

  @property
  def type(self):
    return self._type
