import random
import json
from sqlalchemy.exc import ProgrammingError
from flask import render_template, flash, abort, request
from flask_login import login_required, current_user

try:
    from ...app import app, db, connections, Config
except Exception:
    from app import app, db, connections, Config


@app.route("/sql", methods=["GET", "POST"])
@login_required
def sql():
    if request.method == "GET":
        if not current_user.is_sql:
            flash("You have not permissions to execute sql")
            abort(403)

        return render_template("sql.html", seed=random.randint(0, 10 ** 9), title="Sql editor")

    elif request.method == "POST":
        connection = connections["read_only"]
        if connection is None:
            try:
                import sqlalchemy

                connection = sqlalchemy.create_engine(Config.LIMITED_DATABASE_URI)
                connections["read_only"] = connection
            except Exception:
                pass

        if not current_user.is_sql:
            return json.dumps(
                {
                    "status": "denied",
                    "message": "You have not permissions to execute sql",
                    "keys": [],
                    "data": [],
                }
            )

        if connection is None:
            return json.dumps(
                {
                    "status": "error",
                    "message": "Read-only user does not exists in database",
                    "keys": [],
                    "data": [],
                }
            )

        json_data = request.get_json(force=True)

        try:
            result_proxy = connection.execute(json_data["request"])
            return json.dumps(
                {
                    "status": "OK",
                    "keys": result_proxy.keys(),
                    "data": [row.items() for row in result_proxy.fetchall()],
                }
            )
        except ProgrammingError as e:
            # Works for postgres, mysql and mssql correctly,
            # in other cases return common message about error
            # We don't want to show user full message from database driver because
            # it may contains sensitive information in case of "Permission denied"
            # of "Structure Error", allows intruders to recover full structure of database
            # via special sql requests like
            # https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
            if str(e).lower().find("syntaxerror") > 0:
                return json.dumps({"status": "error", "keys": [], "data": [], "message": "syntax error"})
            else:
                return json.dumps(
                    {
                        "status": "error",
                        "keys": [],
                        "data": [],
                        "message": "database server rejected your request",
                    }
                )
    else:
        abort(501)
