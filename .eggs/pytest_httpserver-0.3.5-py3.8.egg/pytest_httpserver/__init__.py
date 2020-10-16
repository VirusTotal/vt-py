"""
This is package provides the main API for the pytest_httpserver package.

"""

# flake8: noqa

from .httpserver import HTTPServer
from .httpserver import HTTPServerError, Error, NoHandlerError
from .httpserver import WaitingSettings, HeaderValueMatcher, RequestHandler
from .httpserver import URIPattern, URI_DEFAULT, METHOD_ALL
