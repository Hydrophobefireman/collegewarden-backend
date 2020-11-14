# ==================================================
#                  Utility Functions
# ==================================================
from functools import wraps as _wraps
from json import dumps as _dumps
from pathlib import Path
from re import compile as _compile
from time import time as _time
from traceback import print_exc as _print_exc

from flask import Request as _Request
from flask import Response as _Response
from flask import request as _request
from werkzeug.datastructures import Headers

# maybe only strip whitespace?
_sub = _compile(r"([^\w]|_)").sub
sanitize = lambda x: _sub("", x).strip().lower()


def get_origin(request: _Request) -> str:
    """
    for CORS requests
    On client we will send the x-qbytic-origin header
    or a query string to specify the origin

    Args:
        request (_Request): Flask request object

    Returns:
        str: the origin value
    """
    get = request.headers.get
    return get("Origin") or "*"


class ParsedRequest:
    def __init__(self):
        self.args = dict(_request.args)
        self.headers = _request.headers
        self.json: dict = _request.get_json() or {}
        self.method = _request.method
        self.request = _request


def json_response(data: dict, status=200, headers=None) -> _Response:
    dump = _dumps(data)
    resp = _Response(
        dump, status=status, headers=headers, content_type="application/json"
    )
    return resp


def api_response(func):
    # this has to be done otherwise flask will perceive all view_functions as `run`
    @_wraps(func)
    def run(*args, **kwargs):
        try:
            ret = func(*args, **kwargs)
            if isinstance(ret, _Response):
                return ret
            return json_response({"data": ret})

        except AppException as e:

            return json_response({"error": e.message}, status=e.code or 200)
        except Exception as e:
            _print_exc()
            err = "An unknown error occured"
            return json_response({"error": err, "tb": f"{e}"})

    return run


def safe_mkdir(dir_name: str):
    Path(dir_name).mkdir(exist_ok=True)


def safe_remove(filename: str):
    try:
        Path(filename).unlink()
    except:
        pass


def get_bearer_token(headers: Headers) -> str:
    auth = headers.get("Authorization", "")
    # count= 1 as in the rare case that the bearer token itself has the word Bearer in it we want it intact
    return auth.replace("Bearer", "", 1).strip()


class AppException(Exception):
    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message


POST_REQUEST = dict(strict_slashes=False, methods=["post"])
