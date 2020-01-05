import json

from flask import request, abort, redirect, flash, render_template
from flask_login import current_user, login_required

try:
    from ..models import User, Ap, Auth, Client, DataTransfer
    from ...app import app, db
except Exception:
    from app.models import User, Ap, Auth, Client, DataTransfer
    from app import app, db


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if not current_user.is_admin:
        flash("You aren't admin")
        abort(403)

    if request.method == "GET":
        return render_template(
            "admin.html",
            users=db.session.query(User).order_by(User.id).all(),
            aps=db.session.query(Ap).order_by(Ap.id).all(),
            clients=db.session.query(Client).order_by(Client.id).all(),
            datatransfers=db.session.query(DataTransfer).order_by(DataTransfer.id).all(),
            auths=db.session.query(Auth).order_by(Auth.id).all(),
            title="Admin page",
        )
    if request.method == "POST":
        user_id = request.form["id"]
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        is_viewer = request.form.get("is_viewer", False)
        is_collector = request.form.get("is_collector", False)
        is_admin = request.form.get("is_admin", False)
        is_sql = request.form.get("is_sql", False)

        to_bool = lambda x: False if not x else True
        is_viewer = to_bool(is_viewer)
        is_collector = to_bool(is_collector)
        is_admin = to_bool(is_admin)
        is_sql = to_bool(is_sql)

        action = request.form["action"]

        if action == "Edit and save":
            user = User.query.filter_by(id=user_id).first()
            user.username = username
            user.is_viewer = is_viewer
            user.is_admin = is_admin
            user.is_collector = is_collector
            user.is_sql = is_sql

            if password[:7] == "pbkdf2:":
                user.password_hash = password
            else:
                user.set_password(password)

            db.session.commit()

        elif action == "Delete":
            User.query.filter_by(id=user_id).delete()
            db.session.commit()

        return redirect("/admin")

    return abort(405)
