from flask import request as flask_request
from psycopg2 import IntegrityError

from app_init import UserTable, File, db
from auth_token import (
    issue_access_token,
    issue_refresh_token,
    regenerate_access_token,
    require_jwt,
)
from danger import (
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    check_password_hash,
    create_token,
    decode_token,
)

from util import AppException
from util import ParsedRequest as _Parsed
from util import json_response
from util import get_bearer_token

from .common import add_to_db, get_user_by_id, save_to_db
from .cred_manager import CredManager


def register(request: _Parsed):
    json = request.json
    get = json.get
    user = get("user")
    name = get("name")
    password = get("password")

    try:
        user_data = UserTable(user, name, password)
        add_to_db(user_data)
        print("registered ", user)
        return {"user_data": user_data.as_json}
    except Exception as e:
        if isinstance(getattr(e, "orig", None), IntegrityError):
            raise AppException("User exists", 409)
        raise e


def login(request: _Parsed):
    json = request.json
    get = json.get
    user = get("user", "").strip().lower()
    password = get("password", "")
    invalids = []
    if not user:
        invalids.append("username")
    if not password:
        invalids.append("password")
    if invalids:
        raise AppException(f"Invalid {' and '.join(invalids)}", code=401)
    user_data = get_user_by_id(user)
    password_hash = user_data.password_hash
    if not check_password_hash(password_hash, password):
        raise AppException("Incorrect Password", code=401)
    username = user_data.user
    access_token = create_token(issue_access_token(username))
    refresh_token = create_token(issue_refresh_token(username, password_hash))

    return json_response(
        {"data": {"success": True, "user_data": user_data.as_json}},
        headers={"x-access-token": access_token, "x-refresh-token": refresh_token},
    )


def re_authenticate(req: _Parsed):
    headers = flask_request.headers
    access_token = get_bearer_token(headers)
    decoded_access = decode_token(access_token)

    if decoded_access is None:
        refresh_token = headers.get("x-refresh-token")
        decoded_refresh = decode_token(refresh_token)
        access, refresh = regenerate_access_token(decoded_refresh)
        if access is None:
            raise AppException("re-auth", code=401)

        return json_response(
            {},
            headers={
                "x-access-token": create_token(access),
                "x-refresh-token": create_token(refresh),
            },
        )


@require_jwt()
def get_file_list(request: _Parsed, user: str, creds: CredManager = CredManager):
    if creds.user is None or (creds.user != user):
        raise AppException("Not authorized", 403)

    # pylint: disable=no-member
    files = (
        db.session.query(*[c for c in File.__table__.c if c.name != "binary"])
        .filter(File.owner_user == user, File.data_type == "encrypted_blob")
        .all()
    )
    # pylint: enable=no-member
    ret = [f._asdict() for f in files]

    return {"files": ret}


# creds  will be injected by require_jwt
@require_jwt(strict=False)
def get_user_details(request: _Parsed, user: str, creds: CredManager = CredManager):
    current_user = creds.user
    if current_user is not None and (user == "me" or current_user == user.lower()):
        return self_details(request, creds)

    raise AppException("Not authorized", 403)


def self_details(request: _Parsed, creds: CredManager):
    req = get_user_by_id(creds.user)
    resp = req.as_json
    return {"user_data": resp}


@require_jwt()
def check_auth(creds=CredManager):
    user = creds.user
    return {"user_data": get_user_by_id(user).as_json}


@require_jwt()
def reset_password(request: _Parsed, creds=CredManager):
    user = creds.user
    js = request.json
    current_password = js["current_password"]
    new_password = js["new_password"]
    u_data = get_user_by_id(user)
    hashed_pw = u_data.password_hash
    if not check_password_hash(hashed_pw, current_password):
        raise AppException("Incorrect Password", 401)
    u_data.password_hash = new_password
    save_to_db()
    return {
        "user_data": u_data.as_json,
        "message": "Please do not close the window while CollegeWarden re encrypts your files with the new password",
    }
