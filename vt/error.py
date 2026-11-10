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

"""Defines a class to handle errors returned by the VT API."""

import typing


class APIError(Exception):
  """Class that encapsules errors returned by the VirusTotal API."""

  @classmethod
  def from_dict(
      cls, dict_error: typing.Dict, status_code: typing.Optional[int] = None
  ):
    return cls(
        dict_error["code"],
        str(dict_error.get("message")),
        status_code=status_code,
    )

  def __init__(
      self,
      code: str,
      message: str,
      status_code: typing.Optional[int] = None,
  ):
    self.code = code
    self.message = message
    self.status_code = status_code
    super().__init__(code, message)
