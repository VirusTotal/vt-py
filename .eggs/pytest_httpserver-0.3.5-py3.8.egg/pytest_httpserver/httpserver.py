
import queue
import threading
import json
import time
import re
from collections import defaultdict
from enum import Enum
from contextlib import suppress, contextmanager
from copy import copy
from typing import Callable, Mapping, Optional, Union, Pattern
from ssl import SSLContext
import abc

from werkzeug.http import parse_authorization_header
from werkzeug.serving import make_server
from werkzeug.wrappers import Request, Response
import werkzeug.urls
from werkzeug.datastructures import MultiDict

URI_DEFAULT = ""
METHOD_ALL = "__ALL"


class Error(Exception):
    """
    Base class for all exception defined in this package.
    """

    pass


class NoHandlerError(Error):
    """
    Raised when a :py:class:`RequestHandler` has no registered method to serve the request.
    """

    pass


class HTTPServerError(Error):
    """
    Raised when there's a problem with HTTP server.
    """

    pass


class NoMethodFoundForMatchingHeaderValueError(Error):
    """
    Raised when a :py:class:`HeaderValueMatcher` has no registered method to match the header value.
    """

    pass


class WaitingSettings:
    """Class for providing default settings and storing them in HTTPServer

    :param raise_assertions: whether raise assertions on unexpected request or timeout or not
    :param stop_on_nohandler: whether stop on unexpected request or not
    :param timeout: time (in seconds) until time is out
    """

    def __init__(self, raise_assertions: bool = True, stop_on_nohandler: bool = True, timeout: float = 5):
        self.raise_assertions = raise_assertions
        self.stop_on_nohandler = stop_on_nohandler
        self.timeout = timeout


class Waiting:
    """Class for HTTPServer.wait context manager

    This class should not be instantiated directly."""

    def __init__(self):
        self._result = None
        self._start = time.monotonic()
        self._stop = None

    def complete(self, result: bool):
        self._result = result
        self._stop = time.monotonic()

    @property
    def result(self) -> bool:
        return self._result

    @property
    def elapsed_time(self) -> float:
        """Elapsed time in seconds"""
        return self._stop - self._start


class HeaderValueMatcher:
    """
    Matcher object for the header value of incoming request.

    :param matchers: mapping from header name to comparator function that accepts actual and expected header values
        and return whether they are equal as bool.
    """
    DEFAULT_MATCHERS = {}

    def __init__(self, matchers: Optional[Mapping[str, Callable[[str, str], bool]]] = None):
        self.matchers = self.DEFAULT_MATCHERS if matchers is None else matchers

    @staticmethod
    def authorization_header_value_matcher(actual: str, expected: str) -> bool:
        return parse_authorization_header(actual) == parse_authorization_header(expected)

    @staticmethod
    def default_header_value_matcher(actual: str, expected: str) -> bool:
        return actual == expected

    def __call__(self, header_name: str, actual: str, expected: str) -> bool:
        try:
            matcher = self.matchers[header_name]
        except KeyError:
            raise NoMethodFoundForMatchingHeaderValueError(
                "No method found for matching header value: {}".format(header_name))
        return matcher(actual, expected)


HeaderValueMatcher.DEFAULT_MATCHERS = defaultdict(
    lambda: HeaderValueMatcher.default_header_value_matcher,
    {'Authorization': HeaderValueMatcher.authorization_header_value_matcher}
)


class QueryMatcher(abc.ABC):
    """
    Abstract class for QueryMatchers

    get_comparing_values should return a 2-element tuple whose elements will
    be compared.
    """

    def match(self, request_query_string: bytes) -> bool:
        values = self.get_comparing_values(request_query_string)
        return values[0] == values[1]

    @abc.abstractmethod
    def get_comparing_values(self, request_query_string: bytes) -> tuple:
        pass


class StringQueryMatcher(QueryMatcher):
    """
    Matches a query for a string or bytes specified
    """

    def __init__(self, query_string: Union[bytes, str]):
        """
        :param query_string: the query string will be compared to this string or bytes.
            If string is specified, it will be encoded by the encode() method.
            The query must not start with '?' but will be exactly (byte-by-byte) equal
            the actual query string of the incoming request.
        """
        if not isinstance(query_string, (str, bytes)):
            raise TypeError("query_string must be a string, or a bytes-like object")

        self.query_string = query_string

    def get_comparing_values(self, request_query_string: bytes) -> tuple:
        if isinstance(self.query_string, str):
            query_string = self.query_string.encode()
        elif isinstance(self.query_string, bytes):
            query_string = self.query_string
        else:
            raise TypeError("query_string must be a string, or a bytes-like object")

        return (request_query_string, query_string)


class MappingQueryMatcher(QueryMatcher):
    """
    Matches a query string to a dictionary or MultiDict specified
    """

    def __init__(self, query_dict: Union[Mapping, MultiDict]):
        """
        :param query_dict: if dictionary (Mapping) is specified, it will be used as a
            key-value mapping where both key and value should be string. If there are multiple
            values specified for the same key in the request, the first element will be used.
            If you want to match multiple values, use a MultiDict object from werkzeug, which
            represents multiple values for one key.
        """
        self.query_dict = query_dict

    def get_comparing_values(self, request_query_string: bytes) -> tuple:
        query = werkzeug.urls.url_decode(request_query_string)
        if isinstance(self.query_dict, MultiDict):
            return (query, self.query_dict)
        else:
            return (query.to_dict(), dict(self.query_dict))


class BooleanQueryMatcher(QueryMatcher):
    """
    Matches the query depending on the boolean value
    """

    def __init__(self, result: bool):
        """
        :param result: if this parameter is true, the query match will be always
            successful. Otherwise, no query match will be successful.
        """
        self.result = result

    def get_comparing_values(self, request_query_string):
        if self.result:
            return (True, True)
        else:
            return (True, False)


def _create_query_matcher(query_string: Union[None, QueryMatcher, str, bytes, Mapping]) -> QueryMatcher:
    if isinstance(query_string, QueryMatcher):
        return query_string

    if query_string is None:
        return BooleanQueryMatcher(True)

    if isinstance(query_string, (str, bytes)):
        return StringQueryMatcher(query_string)

    if isinstance(query_string, Mapping):
        return MappingQueryMatcher(query_string)

    raise TypeError("Unable to cast this type to QueryMatcher: {!r}".format(type(query_string)))


class URIPattern(abc.ABC):
    @abc.abstractmethod
    def match(self, uri: str) -> bool:
        """
            Matches the provided URI.

            :param uri: URI of the request. This is an absolute path startting
                with "/" and does not contain the query part.
            :return: True if there's a match, False otherwise
            """
        pass


class RequestMatcher:
    """
    Matcher object for the incoming request.

    It defines various parameters to match the incoming request.

    :param uri: URI of the request. This must be an absolute path starting with ``/``, a
        :py:class:`URIPattern` object, or a regular expression compiled by :py:func:`re.compile`.
    :param method: HTTP method of the request. If not specified (or `METHOD_ALL`
        specified), all HTTP requests will match.
    :param data: payload of the HTTP request. This could be a string (utf-8 encoded
        by default, see `data_encoding`) or a bytes object.
    :param data_encoding: the encoding used for data parameter if data is a string.
    :param headers: dictionary of the headers of the request to be matched
    :param query_string: the http query string, after ``?``, such as ``username=user``.
        If string is specified it will be encoded to bytes with the encode method of
        the string. If dict is specified, it will be matched to the ``key=value`` pairs
        specified in the request. If multiple values specified for a given key, the first
        value will be used. If multiple values needed to be handled, use ``MultiDict``
        object from werkzeug.
    """

    def __init__(
            self,
            uri: Union[str, URIPattern, Pattern[str]],
            method: str = METHOD_ALL,
            data: Union[str, bytes, None] = None,
            data_encoding: str = "utf-8",
            headers: Optional[Mapping[str, str]] = None,
            query_string: Union[None, QueryMatcher, str, bytes, Mapping] = None,
            header_value_matcher: Optional[HeaderValueMatcher] = None):

        self.uri = uri
        self.method = method
        self.query_string = query_string
        self.query_matcher = _create_query_matcher(self.query_string)

        if headers is None:
            self.headers = {}
        else:
            self.headers = headers

        if isinstance(data, str):
            data = data.encode(data_encoding)

        self.data = data

        self.header_value_matcher = HeaderValueMatcher() if header_value_matcher is None else header_value_matcher

    def __repr__(self):
        """
        Returns the string representation of the object, with the known parameters.
        """

        class_name = self.__class__.__name__
        retval = "<{} ".format(class_name)
        retval += "uri={uri!r} method={method!r} query_string={query_string!r} headers={headers!r} data={data!r}>".format_map(self.__dict__)
        return retval

    def match_data(self, request: Request) -> bool:
        """
        Matches the data part of the request

        :param request: the HTTP request
        :return: `True` when the data is matched or no matching is required. `False` otherwise.
        """

        if self.data is None:
            return True
        return request.data == self.data

    def match_uri(self, request: Request) -> bool:
        path = request.path

        if isinstance(self.uri, URIPattern):
            return self.uri.match(path)

        # this is python version depending
        # in python 3.7 and above: it is re.Pattern
        # below python 3.7 it is _sre.SRE_Pattern which cannot be accessed directly
        elif isinstance(self.uri, re.compile("").__class__):
            return bool(self.uri.match(path))

        else:
            # there could be a guard isinstance(self.uri, str) been here
            # but we want to allow any object which provides the __eq__ parameter
            # (note: in this case it will be not typeing correct)
            #
            # also, python will raise TypeError when self.uri is a conflicting type

            return self.uri == URI_DEFAULT or path == self.uri

    def difference(self, request: Request) -> list:
        """
        Calculates the difference between the matcher and the request.

        Returns a list of fields where there's a difference between the request and the matcher.
        The returned list may have zero or more elements, each element is a three-element tuple
        containing the field name, the request value, and the matcher value.

        If zero-length list is returned, this means that there's no difference, so the request
        matches the fields set in the matcher object.
        """

        retval = []

        if not self.match_uri(request):
            retval.append(("uri", request.path, self.uri))

        if self.method != METHOD_ALL and self.method != request.method:
            retval.append(("method", request.method, self.method))

        if not self.query_matcher.match(request.query_string):
            retval.append(("query_string", request.query_string, self.query_string))

        request_headers = {}
        expected_headers = {}
        for key, value in self.headers.items():
            if not self.header_value_matcher(key, request.headers.get(key), value):
                request_headers[key] = request.headers.get(key)
                expected_headers[key] = value

        if request_headers and expected_headers:
            retval.append(("headers", request_headers, expected_headers))

        if not self.match_data(request):
            retval.append(("data", request.data, self.data))

        return retval

    def match(self, request: Request) -> bool:
        """
        Returns whether the request matches the parameters set in the matcher
        object or not. `True` value is returned when it matches, `False` otherwise.
        """

        difference = self.difference(request)
        return not difference


class RequestHandler:
    """
    Represents a response function and a :py:class:`RequestHandler` object.

    This class connects the matcher object with the function responsible for the response.

    :param matcher: the matcher object
    """

    def __init__(self, matcher: RequestMatcher):
        self.matcher = matcher
        self.request_handler = None

    def respond(self, request: Request) -> Response:
        """
        Calls the request handler registered for this object.

        If no request handler was specified previously, it raises
        :py:class:`NoHandlerError` exception.

        :param request: the incoming request object
        :return: the response object
        """

        if self.request_handler is None:
            raise NoHandlerError("No handler found for request: {} {}".format(request.method, request.path))
        else:
            return self.request_handler(request)

    def respond_with_json(
            self,
            response_json,
            status: int = 200,
            headers: Optional[Mapping[str, str]] = None,
            content_type: str = "application/json"):
        """
        Registers a respond handler function which responds with a serialized JSON object.

        :param response_json: a JSON-serializable python object
        :param status: the HTTP status of the response
        :param headers: the HTTP headers to be sent (excluding the Content-Type header)
        :param content_type: the content type header to be sent
        """
        response_data = json.dumps(response_json, indent=4)
        self.respond_with_data(response_data, status, headers, content_type=content_type)

    def respond_with_data(
            self,
            response_data: Union[str, bytes] = "",
            status: int = 200,
            headers: Optional[Mapping[str, str]] = None,
            mimetype: Optional[str] = None,
            content_type: Optional[str] = None):
        """
        Registers a respond handler function which responds raw data.

        For detailed description please see the :py:class:`Response` object as the
        parameters are analogue.

        :param response_data: a string or bytes object representing the body of the response
        :param status: the HTTP status of the response
        :param headers: the HTTP headers to be sent (excluding the Content-Type header)
        :param content_type: the content type header to be sent
        :param mimetype: the mime type of the request

        """
        def handler(request):  # pylint: disable=unused-argument
            return Response(response_data, status, headers, mimetype, content_type)

        self.request_handler = handler

    def respond_with_response(self, response: Response):
        """
        Registers a respond handler function which responds the specified response object.

        :param response: the response object which will be responded

        """
        self.request_handler = lambda request: response

    def respond_with_handler(self, func: Callable[[Request], Response]):
        """
        Registers the specified function as a responder.

        The function will receive the request object and must return with the response object.
        """
        self.request_handler = func


class RequestHandlerList(list):
    """
    Represents a list of :py:class:`RequestHandler` objects.

    """

    def match(self, request: Request) -> RequestHandler:
        """
        Returns the first request handler which matches the specified request. Otherwise, it returns `None`.
        """
        for requesthandler in self:
            if requesthandler.matcher.match(request):
                return requesthandler
        return None


class HandlerType(Enum):
    PERMANENT = 'permanent'
    ONESHOT = 'oneshot'
    ORDERED = 'ordered'


class HTTPServer:   # pylint: disable=too-many-instance-attributes
    """
    Server instance which manages handlers to serve pre-defined requests.

    :param host: the host or IP where the server will listen
    :param port: the TCP port where the server will listen
    :param ssl_context: the ssl context object to use for https connections
    :param default_waiting_settings: the waiting settings object to use as default settings for :py:meth:`wait` context
        manager

    .. py:attribute:: log

        Attribute containing the list of two-element tuples. Each tuple contains
        :py:class:`Request` and :py:class:`Response` object which represents the
        incoming request and the outgoing response which happened during the lifetime
        of the server.
    """

    DEFAULT_LISTEN_HOST = "localhost"
    DEFAULT_LISTEN_PORT = 0  # Use ephemeral port

    def __init__(self, host=DEFAULT_LISTEN_HOST, port=DEFAULT_LISTEN_PORT, ssl_context: Optional[SSLContext] = None,
                 default_waiting_settings: Optional[WaitingSettings] = None):
        """
        Initializes the instance.

        """
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self.assertions = []
        self.log = []
        self.ordered_handlers = []
        self.oneshot_handlers = RequestHandlerList()
        self.handlers = RequestHandlerList()
        self.permanently_failed = False
        self.ssl_context = ssl_context
        if default_waiting_settings is not None:
            self.default_waiting_settings = default_waiting_settings
        else:
            self.default_waiting_settings = WaitingSettings()
        self._waiting_settings = copy(self.default_waiting_settings)
        self._waiting_result = queue.LifoQueue(maxsize=1)

    def clear(self):
        """
        Clears and resets the state attributes of the object.

        This method is useful when the object needs to be re-used but stopping the server is not feasible.

        """
        self.clear_assertions()
        self.clear_log()
        self.clear_all_handlers()
        self.permanently_failed = False

    def clear_assertions(self):
        """
        Clears the list of assertions
        """

        self.assertions = []

    def clear_log(self):
        """
        Clears the list of log entries
        """

        self.log = []

    def clear_all_handlers(self):
        """
        Clears all types of the handlers (ordered, oneshot, permanent)
        """

        self.ordered_handlers = []
        self.oneshot_handlers = RequestHandlerList()
        self.handlers = RequestHandlerList()

    def url_for(self, suffix: str):
        """
        Return an url for a given suffix.

        This basically means that it prepends the string ``http://$HOST:$PORT/`` to the `suffix` parameter
        (where $HOST and $PORT are the parameters given to the constructor).

        :param suffix: the suffix which will be added to the base url. It can start with ``/`` (slash) or
            not, the url will be the same.
        :return: the full url which refers to the server
        """

        if not suffix.startswith("/"):
            suffix = "/" + suffix

        if self.ssl_context is None:
            protocol = "http"
        else:
            protocol = "https"

        return "{}://{}:{}{}".format(protocol, self.host, self.port, suffix)

    def create_matcher(self, *args, **kwargs) -> RequestMatcher:
        """
        Creates a :py:class:`RequestMatcher` instance with the specified parameters.

        This method can be overridden if you want to use your own matcher.
        """

        return RequestMatcher(*args, **kwargs)

    def expect_request(
            self,
            uri: Union[str, URIPattern, Pattern[str]],
            method: str = METHOD_ALL,
            data: Union[str, bytes, None] = None,
            data_encoding: str = "utf-8",
            headers: Optional[Mapping[str, str]] = None,
            query_string: Union[None, QueryMatcher, str, bytes, Mapping] = None,
            header_value_matcher: Optional[HeaderValueMatcher] = None,
            handler_type: HandlerType = HandlerType.PERMANENT) -> RequestHandler:
        """
        Create and register a request handler.

        If `handler_type` is `HandlerType.PERMANENT` a permanent request handler is created. This handler can be used as
        many times as the request matches it, but ordered handlers have higher priority so if there's one or more
        ordered handler registered, those must be used first.

        If `handler_type` is `HandlerType.ONESHOT` a oneshot request handler is created. This handler can be only used
        once. Once the server serves a response for this handler, the handler will be dropped.

        If `handler_type` is `HandlerType.ORDERED` an ordered request handler is created. Comparing to oneshot handler,
        ordered handler also determines the order of the requests to be served. For example if there are two ordered
        handlers registered, the first request must hit the first handler, and the second request must hit the second
        one, and not vice versa. If one or more ordered handler defined, those must be exhausted first.


        :param uri: URI of the request. This must be an absolute path starting with ``/``, a
            :py:class:`URIPattern` object, or a regular expression compiled by :py:func:`re.compile`.
        :param method: HTTP method of the request. If not specified (or `METHOD_ALL`
            specified), all HTTP requests will match.
        :param data: payload of the HTTP request. This could be a string (utf-8 encoded
            by default, see `data_encoding`) or a bytes object.
        :param data_encoding: the encoding used for data parameter if data is a string.
        :param headers: dictionary of the headers of the request to be matched
        :param query_string: the http query string, after ``?``, such as ``username=user``.
            If string is specified it will be encoded to bytes with the encode method of
            the string. If dict is specified, it will be matched to the ``key=value`` pairs
            specified in the request. If multiple values specified for a given key, the first
            value will be used. If multiple values needed to be handled, use ``MultiDict``
            object from werkzeug.
        :param header_value_matcher: :py:class:`HeaderValueMatcher` that matches values of headers.
        :param handler_type: type of handler

        :return: Created and register :py:class:`RequestHandler`.
        """

        matcher = self.create_matcher(
            uri,
            method=method,
            data=data,
            data_encoding=data_encoding,
            headers=headers,
            query_string=query_string,
            header_value_matcher=header_value_matcher,
        )
        request_handler = RequestHandler(matcher)
        if handler_type == HandlerType.PERMANENT:
            self.handlers.append(request_handler)
        elif handler_type == HandlerType.ONESHOT:
            self.oneshot_handlers.append(request_handler)
        elif handler_type == HandlerType.ORDERED:
            self.ordered_handlers.append(request_handler)
        return request_handler

    def expect_oneshot_request(
            self,
            uri: Union[str, URIPattern, Pattern[str]],
            method: str = METHOD_ALL,
            data: Union[str, bytes, None] = None,
            data_encoding: str = "utf-8",
            headers: Optional[Mapping[str, str]] = None,
            query_string: Union[None, QueryMatcher, str, bytes, Mapping] = None,
            header_value_matcher: Optional[HeaderValueMatcher] = None) -> RequestHandler:
        """
        Create and register a oneshot request handler.

        This is a method for convenience. See :py:meth:`expect_request` for documentation.

        :param uri: URI of the request. This must be an absolute path starting with ``/``, a
            :py:class:`URIPattern` object, or a regular expression compiled by :py:func:`re.compile`.
        :param method: HTTP method of the request. If not specified (or `METHOD_ALL`
            specified), all HTTP requests will match.
        :param data: payload of the HTTP request. This could be a string (utf-8 encoded
            by default, see `data_encoding`) or a bytes object.
        :param data_encoding: the encoding used for data parameter if data is a string.
        :param headers: dictionary of the headers of the request to be matched
        :param query_string: the http query string, after ``?``, such as ``username=user``.
            If string is specified it will be encoded to bytes with the encode method of
            the string. If dict is specified, it will be matched to the ``key=value`` pairs
            specified in the request. If multiple values specified for a given key, the first
            value will be used. If multiple values needed to be handled, use ``MultiDict``
            object from werkzeug.
        :param header_value_matcher: :py:class:`HeaderValueMatcher` that matches values of headers.

        :return: Created and register :py:class:`RequestHandler`.
        """

        return self.expect_request(
            uri=uri,
            method=method,
            data=data,
            data_encoding=data_encoding,
            headers=headers,
            query_string=query_string,
            header_value_matcher=header_value_matcher,
            handler_type=HandlerType.ONESHOT,
        )

    def expect_ordered_request(
            self,
            uri: Union[str, URIPattern, Pattern[str]],
            method: str = METHOD_ALL,
            data: Union[str, bytes, None] = None,
            data_encoding: str = "utf-8",
            headers: Optional[Mapping[str, str]] = None,
            query_string: Union[None, QueryMatcher, str, bytes, Mapping] = None,
            header_value_matcher: Optional[HeaderValueMatcher] = None) -> RequestHandler:
        """
        Create and register a ordered request handler.

        This is a method for convenience. See :py:meth:`expect_request` for documentation.

        :param uri: URI of the request. This must be an absolute path starting with ``/``, a
            :py:class:`URIPattern` object, or a regular expression compiled by :py:func:`re.compile`.
        :param method: HTTP method of the request. If not specified (or `METHOD_ALL`
            specified), all HTTP requests will match.
        :param data: payload of the HTTP request. This could be a string (utf-8 encoded
            by default, see `data_encoding`) or a bytes object.
        :param data_encoding: the encoding used for data parameter if data is a string.
        :param headers: dictionary of the headers of the request to be matched
        :param query_string: the http query string, after ``?``, such as ``username=user``.
            If string is specified it will be encoded to bytes with the encode method of
            the string. If dict is specified, it will be matched to the ``key=value`` pairs
            specified in the request. If multiple values specified for a given key, the first
            value will be used. If multiple values needed to be handled, use ``MultiDict``
            object from werkzeug.
        :param header_value_matcher: :py:class:`HeaderValueMatcher` that matches values of headers.

        :return: Created and register :py:class:`RequestHandler`.
        """

        return self.expect_request(
            uri=uri,
            method=method,
            data=data,
            data_encoding=data_encoding,
            headers=headers,
            query_string=query_string,
            header_value_matcher=header_value_matcher,
            handler_type=HandlerType.ORDERED,
        )

    def thread_target(self):
        """
        This method serves as a thread target when the server is started.

        This should not be called directly, but can be overriden to tailor it to your needs.
        """

        self.server.serve_forever()

    def is_running(self) -> bool:
        """
        Returns `True` when the server is running, otherwise `False`.
        """
        return bool(self.server)

    def start(self):
        """
        Start the server in a thread.

        This method returns immediately (e.g. does not block), and it's the caller's
        responsibility to stop the server (by calling :py:meth:`stop`) when it is no longer needed).

        If the sever is not stopped by the caller and execution reaches the end, the
        program needs to be terminated by Ctrl+C or by signal as it will not terminate until
        the thred is stopped.

        If the sever is already running :py:class:`HTTPServerError` will be raised. If you are
        unsure, call :py:meth:`is_running` first.

        There's a context interface of this class which stops the server when the context block ends.
        """
        if self.is_running():
            raise HTTPServerError("Server is already running")

        self.server = make_server(self.host, self.port, self.application, ssl_context=self.ssl_context)
        self.port = self.server.port  # Update port (needed if `port` was set to 0)
        self.server_thread = threading.Thread(target=self.thread_target)
        self.server_thread.start()

    def stop(self):
        """
        Stop the running server.

        Notifies the server thread about the intention of the stopping, and the thread will
        terminate itself. This needs about 0.5 seconds in worst case.

        Only a running server can be stopped. If the sever is not runnig, :py:class`HTTPServerError`
        will be raised.
        """
        if not self.is_running():
            raise HTTPServerError("Server is not running")
        self.server.shutdown()
        self.server_thread.join()
        self.server = None
        self.server_thread = None

    def add_assertion(self, obj):
        """
        Add a new assertion

        Assertions can be added here, and when :py:meth:`check_assertions` is called,
        it will raise AssertionError for pytest with the object specified here.

        :param obj: An object which will be passed to AssertionError.
        """
        self.assertions.append(obj)

    def check_assertions(self):
        """
        Raise AssertionError when at least one assertion added

        The first assertion added by :py:meth:`add_assertion` will be raised and
        it will be removed from the list.

        This method can be useful to get some insights into the errors happened in
        the sever, and to have a proper error reporting in pytest.
        """

        if self.assertions:
            raise AssertionError(self.assertions.pop(0))

    def format_matchers(self) -> str:
        """
        Return a string representation of the matchers

        This method returns a human-readable string representation of the matchers
        registered. You can observe which requests will be served, etc.

        This method is primairly used when reporting errors.
        """
        def format_handlers(handlers):
            if handlers:
                return ["    {!r}".format(handler.matcher) for handler in handlers]
            else:
                return ["    none"]

        lines = []
        lines.append("Ordered matchers:")
        lines.extend(format_handlers(self.ordered_handlers))
        lines.append("")
        lines.append("Oneshot matchers:")
        lines.extend(format_handlers(self.oneshot_handlers))
        lines.append("")
        lines.append("Persistent matchers:")
        lines.extend(format_handlers(self.handlers))

        return "\n".join(lines)

    def respond_nohandler(self, request: Request):
        """
        Add a 'no handler' assertion.

        This method is called when the server wasn't able to find any handler to serve the request.
        As the result, there's an assertion added (which can be raised by :py:meth:`check_assertions`).

        """
        if self._waiting_settings.stop_on_nohandler:
            self._set_waiting_result(False)
        text = "No handler found for request {!r}.\n".format(request)
        self.add_assertion(text + self.format_matchers())
        return Response("No handler found for this request", 500)

    def respond_permanent_failure(self):
        """
        Add a 'permanent failure' assertion.

        This assertion means that no further requests will be handled. This is the resuld of missing
        an ordered matcher.

        """

        self.add_assertion("All requests will be permanently failed due failed ordered handler")
        return Response("No handler found for this request", 500)

    def dispatch(self, request: Request) -> Response:
        """
        Dispatch a request to the appropriate request handler.

        This method tries to find the request handler whose matcher matches the request, and
        then calls it in order to serve the request.

        First, the request is checked for the ordered matchers. If there's an ordered matcher,
        it must match the request, otherwise the server will be put into a `permanent failure`
        mode in which it makes all request failed - this is the intended way of working of ordered
        matchers.

        Then oneshot handlers, and the permanent handlers are looked up.

        :param request: the request object from the werkzeug library
        :return: the response object what the handler responded, or a response which contains the error
        """

        if self.permanently_failed:
            return self.respond_permanent_failure()

        handler = None
        if self.ordered_handlers:
            handler = self.ordered_handlers[0]
            if not handler.matcher.match(request):
                self.permanently_failed = True
                response = self.respond_nohandler(request)
                return response

            self.ordered_handlers.pop(0)
            self._update_waiting_result()

        if not handler:
            handler = self.oneshot_handlers.match(request)
            if handler:
                self.oneshot_handlers.remove(handler)
                self._update_waiting_result()
            else:
                handler = self.handlers.match(request)

            if not handler:
                return self.respond_nohandler(request)

        response = handler.respond(request)

        if response is None:
            response = Response("")
        if isinstance(response, str):
            response = Response(response)

        return response

    def _set_waiting_result(self, value: bool) -> None:
        """Set waiting_result

        Setting is implemented as putting value to queue without waiting. If queue is full we simply ignore the
        exception, because that means that waiting_result was already set, but not read.
        """
        with suppress(queue.Full):
            self._waiting_result.put_nowait(value)

    def _update_waiting_result(self) -> None:
        if not self.oneshot_handlers and not self.ordered_handlers:
            self._set_waiting_result(True)

    @contextmanager
    def wait(self, raise_assertions: Optional[bool] = None, stop_on_nohandler: Optional[bool] = None,
             timeout: Optional[float] = None):
        """Context manager to wait until the first of following event occurs: all ordered and oneshot handlers were
        executed, unexpected request was received (if `stop_on_nohandler` is set to `True`), or time was out

        :param raise_assertions: whether raise assertions on unexpected request or timeout or not
        :param stop_on_nohandler: whether stop on unexpected request or not
        :param timeout: time (in seconds) until time is out

        Example:

        .. code-block:: python

            def test_wait(httpserver):
                httpserver.expect_oneshot_request('/').respond_with_data('OK')
                with httpserver.wait(raise_assertions=False, stop_on_nohandler=False, timeout=1) as waiting:
                    requests.get(httpserver.url_for('/'))
                # `waiting` is :py:class:`Waiting`
                assert waiting.result
                print('Elapsed time: {} sec'.format(waiting.elapsed_time))
        """
        if raise_assertions is None:
            self._waiting_settings.raise_assertions = self.default_waiting_settings.raise_assertions
        else:
            self._waiting_settings.raise_assertions = raise_assertions
        if stop_on_nohandler is None:
            self._waiting_settings.stop_on_nohandler = self.default_waiting_settings.stop_on_nohandler
        else:
            self._waiting_settings.stop_on_nohandler = stop_on_nohandler
        if timeout is None:
            self._waiting_settings.timeout = self.default_waiting_settings.timeout
        else:
            self._waiting_settings.timeout = timeout

        # Ensure that waiting_result is empty
        with suppress(queue.Empty):
            self._waiting_result.get_nowait()

        waiting = Waiting()
        yield waiting

        try:
            waiting_result = self._waiting_result.get(timeout=self._waiting_settings.timeout)
            waiting.complete(result=waiting_result)
        except queue.Empty:
            waiting.complete(result=False)
            if self._waiting_settings.raise_assertions:
                raise AssertionError('Wait timeout occurred, but some handlers left:\n'
                                     '{}'.format(self.format_matchers()))
        if self._waiting_settings.raise_assertions and not waiting.result:
            self.check_assertions()

    @Request.application
    def application(self, request: Request):
        """
        Entry point of werkzeug.

        This method is called for each request, and it then calls the undecorated
        :py:meth:`dispatch` method to serve the request.

        :param request: the request object from the werkzeug library
        :return: the response object what the dispatch returned
        """
        request.get_data()
        response = self.dispatch(request)
        self.log.append((request, response))
        return response

    def __enter__(self):
        """
        Provide the context API

        It starts the server in a thread if the server is not already running.
        """

        if not self.is_running():
            self.start()
        return self

    def __exit__(self, *args, **kwargs):
        """
        Provide the context API

        It stops the server if the server is running.
        Please note that depending on the internal things of werkzeug, it may take 0.5 seconds.
        """
        if self.is_running():
            self.stop()
