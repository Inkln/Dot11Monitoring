import os
from base64 import b64encode

from Crypto.Random import get_random_bytes

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URI", "postgresql://dot11admin:dot11password@localhost/dot11monitor"
    )
    LIMITED_DATABASE_URI = os.environ.get(
        "LIMITED_DATABASE_URI", "postgresql://dot11viewer:dot11password@localhost/dot11monitor"
    )
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", b64encode(get_random_bytes(12)).decode("utf-8"))
    SECRET_KEY = os.environ.get("SECRET_KEY", b64encode(get_random_bytes(256)))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TEMPLATES_AUTO_RELOAD = True
