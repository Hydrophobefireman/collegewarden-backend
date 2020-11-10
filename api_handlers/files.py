from base64 import b64decode

from app_init import File
from auth_token import require_jwt
from flask import Response
from util import AppException, ParsedRequest

from .common import (
    add_to_db,
    delete_from_db,
    get_file_by_id,
    get_user_by_id,
    save_to_db,
)
from .cred_manager import CredManager


def ensure_file_owner(file_id: str, user: str) -> File:
    file = get_file_by_id(file_id)
    if file.owner_user != user:
        raise AppException("Not authorized to delete this file", code=401)
    return file


@require_jwt()
def upload(request: ParsedRequest, creds: CredManager = None):
    file = ensure_limit(request.request.get_data())
    user = creds.user
    iv = request.headers["x-cw-iv"]
    data_type = request.headers["x-cw-data-type"]
    data = File(user, iv, file, data_type)
    idx = data.file_id
    add_to_db(data)
    return {"status": True, "file_id": idx}


@require_jwt()
def edit(request: ParsedRequest, file_id: str, creds: CredManager = None):
    file = ensure_file_owner(file_id, creds.user)
    new_data = ensure_limit(request.request.get_data())
    file.binary = new_data
    save_to_db()
    return {"status": True}


@require_jwt()
def delete(request: ParsedRequest, creds: CredManager = None):
    file_id = request.json["file_id"]
    user = creds.user
    file = ensure_file_owner(file_id, user)
    delete_from_db(file)
    return {"status": True}


@require_jwt()
def get_file(file_id: str, creds: CredManager = None):
    file = ensure_file_owner(file_id, creds.user).binary
    return Response(file, headers={"content-type": "application/octet-stream"})


@require_jwt()
def upload_info(request: ParsedRequest, creds: CredManager = None):
    user = creds.user
    user_data = get_user_by_id(user)
    file = ensure_limit(request.request.get_data())
    iv = request.headers["x-cw-iv"]
    if user_data.info_dict_id is not None:
        file_data = get_file_by_id(user_data.info_dict_id)
        file_data.file_enc_meta = iv
        file_data.binary = file
    else:
        file_data = File(user, iv, file, "encrypted_json")
        user_data.info_dict_id = file_data.file_id
        add_to_db(file_data, True)
    save_to_db()
    return {"success": True}


@require_jwt()
def get_info(request: ParsedRequest, creds: CredManager = None):
    user = creds.user
    user_data = get_user_by_id(user)
    file = user_data.info_dict_id
    if file is None:
        return {"info_dict": None}
    return {"info_dict": get_file_by_id(file).as_json}


ten_mb = 10 * 1024 * 1024


def ensure_limit(b: bytes):
    if len(b) > ten_mb:
        raise AppException("file too large!")
    return b