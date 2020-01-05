import os

from flask import Flask

try:
    from config import Config
except Exception:
    from Api.config import Config

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from werkzeug.security import generate_password_hash

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

# database connection to allow users write own sql. MUST BE SAFETY or RDONLY
# and have LIMITED PERMISSIONS
connections = {}
try:
    import sqlalchemy

    connections["read_only"] = sqlalchemy.create_engine(Config.LIMITED_DATABASE_URI)
except Exception:
    pass


try:
    from ..app import routes
except Exception:
    from app import routes


login.login_view = "index"


@app.before_first_request
def insert_admin_into_db():
    admin_from_db = db.session.query(models.User).filter_by(username="admin").first()
    if admin_from_db is not None:
        return

    admin_password = Config.ADMIN_PASSWORD
    print("User 'admin' created with password:", admin_password)
    admin = models.User(
        username="admin",
        password_hash=generate_password_hash(admin_password),
        is_collector=True,
        is_admin=True,
        is_viewer=True,
        is_sql=True,
    )
    db.session.add(admin)
    db.session.commit()
