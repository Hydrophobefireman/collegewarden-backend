from os import environ
from secrets import token_urlsafe
from time import time
from typing import List

from flask import Flask, Response, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from floodgate import guard
from sqlalchemy.orm import validates

from constants import DATABASE_URL, FLASK_SECRET, IS_PROD
from danger import check_password_hash, generate_password_hash
from util import AppException, get_origin, json_response, sanitize

app = Flask(__name__)
app.secret_key = FLASK_SECRET
database_url: str = DATABASE_URL

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# not exactly as we have 4 workers running, it's basically a lottery if you hit the same worker thrice
# gate = Gate(use_heroku_ip_resolver=IS_PROD, limit=1, min_requests=3)


@app.before_request
@guard(ban_time=5, ip_resolver="heroku" if IS_PROD else None, request_count=30, per=60)
def gate_check():
    pass


@app.route("/robots.txt")
def robots():
    ONE_YEAR_IN_SECONDS = 60 * 60 * 24 * 365
    # we disallow all bots here because we don't want useless crawling over the API
    return send_from_directory(
        "static", "robots.txt", cache_timeout=ONE_YEAR_IN_SECONDS
    )


@app.errorhandler(404)
def catch_all(e):
    return json_response({"error": "not found"})


@app.errorhandler(405)
def method_not_allowed(e):
    return json_response({"error": "Method not allowed"})


EXPOSE_HEADERS = ", ".join(
    ("x-access-token", "x-refresh-token", "x-dynamic", "x-file-meta")
)


@app.after_request
def cors(resp):
    origin = get_origin(request)
    resp.headers["access-control-allow-origin"] = origin
    resp.headers["access-control-allow-headers"] = request.headers.get(
        "access-control-request-headers", "*"
    )
    resp.headers["access-control-allow-credentials"] = "true"
    resp.headers["x-dynamic"] = "true"
    resp.headers["access-control-max-age"] = "86400"
    resp.headers["access-control-expose-headers"] = EXPOSE_HEADERS
    return resp


class UserTable(db.Model):
    # pylint: disable=E1101
    user: str = db.Column(db.String(30), primary_key=True)
    name: str = db.Column(db.String(30), nullable=False)
    password_hash: str = db.Column(db.String, nullable=False)
    created_at: int = db.Column(db.Integer)
    files: List = db.relationship("File", backref="enc", lazy=True)
    info_dict_id: str = db.Column(db.String)
    # pylint: enable=E1101

    @property
    def as_json(self):
        return {
            "name": self.name,
            "user": self.user,
            "created_at": self.created_at,
            "_secure_": {"info_dict_id": self.info_dict_id},
        }

    @validates("user")
    def _validate_user(self, _key, user: str):
        length = len(user)
        if length > 30:
            raise AppException("Username cannot be longer than 30 characters", 400)
        if length < 4:
            raise AppException("Username cannot be shorter than 4 characters", 400)
        if sanitize(user) != user:
            raise AppException(
                "Username cannot have special characters or whitespace", 400
            )
        return user

    @validates("password_hash")
    def _validate_password(self, _key, password: str):
        length = len(password)
        if length < 4:
            raise AppException("Password cannot be shorter than 4 characters", 400)
        return generate_password_hash(password)

    def __init__(
        self,
        user: str = None,
        name: str = None,
        password: str = None,
        created_at: int = None,
        info_dict_id: str = None,
    ):
        raise_if_invalid_data(user, name, password)
        self.user = user.lower()
        self.name = name
        self.password_hash = password
        self.info_dict_id = None


ENCRYPTED_JSON = "encrypted_json"
ENCRYPTED_BLOB = "encrypted_blob"


class File(db.Model):
    # pylint: disable=E1101
    owner_user: str = db.Column(
        db.String(30), db.ForeignKey(UserTable.user, ondelete="cascade")
    )
    file_enc_meta: str = db.Column(db.String, nullable=False)
    binary: bytes = db.Column(db.LargeBinary, nullable=False)
    file_id: str = db.Column(db.String, primary_key=True)
    data_type: str = db.Column(db.String(20), nullable=False)
    # pylint: enable=E1101
    def __init__(
        self,
        owner_user: str = None,
        file_enc_meta: str = None,
        binary: bytes = None,
        data_type: str = None,
    ):
        raise_if_invalid_data(owner_user, file_enc_meta, data_type)
        self.owner_user = owner_user
        self.file_enc_meta = file_enc_meta
        self.binary = binary
        self.file_id = token_urlsafe(30)
        self.data_type = data_type

    @property
    def as_json(self):
        return {
            "file_enc_meta": self.file_enc_meta,
            "owner": self.owner_user,
            "file_id": self.file_id,
            "data_type": self.data_type,
        }

    @validates("owner_user")
    def _validate_owner_user(self, _, u: str):
        raise_if_invalid_data(u)
        return u

    @validates("data_type")
    def _validate_data_type(self, _k, t: str):
        if t in (ENCRYPTED_JSON, ENCRYPTED_BLOB):
            return t
        raise AppException("Invalid value for 'data_type'", 400)


def raise_if_invalid_data(*args):
    if any(not x or not ((x).strip() if isinstance(x, str) else True) for x in args):
        raise AppException("Invalid Data", 400)
