try:
    from ..app import app, db
except Exception:
    from app import app, db

from .handles import *


@app.route("/", methods=["GET"])
@app.route("/index", methods=["GET"])
def index():
    return render_template("index.html", form_login=LoginForm(), form_register=RegisterForm())
