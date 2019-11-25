import os
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'app.db'))
    SECRET_KEY = os.environ.get("SECRET_KEY", b64encode(get_random_bytes(256)))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TEMPLATES_AUTO_RELOAD = True

