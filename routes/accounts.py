from flask import request, Response

from api_handlers import users
from app_init import app
from util import POST_REQUEST, ParsedRequest, api_response, json_response


# user registration route
# POST request
@app.route("/accounts/register/", **POST_REQUEST)
@app.route("/register", **POST_REQUEST)
@api_response
def register():
    return users.register(ParsedRequest())


@app.route("/accounts/login", **POST_REQUEST)
@api_response
def login():
    return users.login(ParsedRequest())


@app.route("/accounts/whoami/", strict_slashes=False)
@api_response
def check_auth_resp():
    return users.check_auth()


# refresh the JWT Token
# GET request
@app.route("/accounts/token/refresh/", strict_slashes=False)
@api_response
def refesh_token():
    return users.re_authenticate(ParsedRequest())


@app.route("/accounts/password/new/", **POST_REQUEST)
@api_response
def reset_password():
    return users.reset_password(ParsedRequest())


# ===========================================================================
#                                  Users


# Get user info, secure data is removed for unauthenticated
# requests
@app.route("/accounts/<user>/", strict_slashes=False)
@api_response
def user_details(user):
    return users.get_user_details(ParsedRequest(), user)


@app.route("/accounts/<user>/files/", strict_slashes=False)
@api_response
def get_files(user):
    return users.get_file_list(ParsedRequest(), user)


@app.route("/logout/", strict_slashes=False)
@api_response
def log_user_out():
    return json_response({}, headers={"x-access-token": "", "x-refresh-token": ""})


# debugging, stub for state sync in the future
@app.route("/_interact/", strict_slashes=False)
def check_net():
    print(request.args)
    return Response("", status=204)
