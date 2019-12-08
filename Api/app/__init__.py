from flask import Flask
from .config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash

from Crypto.Random import get_random_bytes
from base64 import b64encode

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)

from .utils.vendors import OfflineVendorsParser
vendors_provider = OfflineVendorsParser()

try:
    from ..app import models
except Exception:
    from app import models

from .utils.graph_builder import GraphBuilder
graph_builder = GraphBuilder(db=db)

try:
    from ..app import routes
except Exception:
    from app import routes


login.login_view = 'index'

@app.before_first_request
def insert_admin_into_db():
    admin_from_db = db.session.query(models.User).filter_by(username='admin').first()
    if admin_from_db is not None:
        return

    admin_password = b64encode(get_random_bytes(12)).decode('utf-8')
    print('User \'admin\' created with password:', admin_password)
    admin = models.User(username='admin', password_hash=generate_password_hash(admin_password),
                        is_collector=True, is_admin=True, is_viewer=True)
    db.session.add(admin)
    db.session.commit()
