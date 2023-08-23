#!/usr/bin/python
#
# Copyright 2017 Google Inc. All Rights Reserved.

"""Module for querying data structures using JsonPath syntax.

This module is a simpler interface for jsonpath_ng, which implements a mechanism
for querying JSON data structures. JsonPath is to JSON what XPath is to XML.
JsonPath was as proposed in http://goessner.net/articles/JsonPath/.
See https://github.com/h2non/jsonpath-ng for details about JsonPath.
"""

import jsonpath_ng

# Parsing a JsonPath is slow, and we use the same paths in multiple places
# across the codebase. We store the already parsed paths in _PARSED_PATH_CACHE
# and reuse them instead of parsing them again.

_PARSED_PATH_CACHE = {}


class DictPathException(Exception):
  """Represents exceptions raised by the dictpath module."""


def iterate(data, path):
  """Generator that returns values in data matching the given JsonPath."""

  if not data:
    return

  parsed_path = _PARSED_PATH_CACHE.get(path)

  if not parsed_path:
    parsed_path = jsonpath_ng.parse(path)
    _PARSED_PATH_CACHE[path] = parsed_path

  for item in parsed_path.find(data):
    yield item.value


def get_all(data, path):
  """Returns a list with all values in data matching the given JsonPath."""
  return list(iterate(data, path))


def get(data, path, default=None):
  """Returns the value in data matching the given JsonPath.

  If the path matches more than one value an exception is raised.
  Args:
    data: Data to be queried.
    path: Query string in JsonPath format.
    default: Value returned when there are no results.

  Returns:
    The value in data matching the given path.
  Raises:
    Exception: If the provided path matches more than one value.
  """
  result = get_all(data, path)
  if not result:
    return default
  if len(result) > 1:
    raise DictPathException(f"JsonPath {path} returning more than one value")
  return result[0]
