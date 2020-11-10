from set_env import setup_env

setup_env()

from app_init import app
from routes import accounts, files


if __name__ == "__main__":
    app.run(debug=True)
