from os import environ as _environ
from set_env import setup_env as _setup_env


_setup_env()

IS_PROD = _environ.get("IS_PROD") is not None

# JWT Signing key, make sure this stays same or every user will need to relogin
SIGNING_KEY = _environ.get("JWT_SIGNING_KEY")
# How long an access_token will last
TOKEN_EXPIRATION_TIME_IN_SECONDS = 60 * float(_environ.get("TOKEN_EXPIRATION_TIME"))

FLASK_SECRET = _environ.get("FLASK_SECRET")
DATABASE_URL = _environ.get("DATABASE_URL")
REFRESH_TOKEN_SALT = _environ.get("REFRESH_TOKEN_SALT")
del _environ
