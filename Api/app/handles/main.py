from flask import render_template
from flask_login import login_required, current_user

try:
    from ...app import app, db
except Exception:
    from app import app, db


@app.route("/main_page", methods=["GET"])
@login_required
def main_page():
    return render_template("main.html", user=current_user, title="Main")
