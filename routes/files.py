from flask import request

from api_handlers import files
from app_init import app
from util import POST_REQUEST, ParsedRequest, api_response, json_response


@app.route("/info/", strict_slashes=False)
@api_response
def get_encrypted_info():
    return files.get_info(ParsedRequest())


@app.route("/info/upload/", **POST_REQUEST)
@api_response
def upload_encrypted_info():
    return files.upload_info(ParsedRequest())


@app.route("/files/upload/", **POST_REQUEST)
@api_response
def upload():
    return files.upload(ParsedRequest())


@app.route("/files/<file_id>/", strict_slashes=False)
@api_response
def get_encrypted_file(file_id):
    return files.get_file(file_id)


@app.route("/files/<file_id>/delete/", **POST_REQUEST)
@api_response
def delete_file(file_id):
    return files.delete(ParsedRequest())


@app.route("/files/<file_id>/edit/", **POST_REQUEST)
@api_response
def edit_file(file_id):
    return files.edit(ParsedRequest(), file_id)
