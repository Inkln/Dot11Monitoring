try:
    from ...app import app, db
except Exception:
    from app import app, db

import random
import json
from flask import render_template, redirect, flash, abort, request
from flask_login import login_required, current_user


@app.route('/sql', methods=['GET', 'POST'])
@login_required
def sql():
    if request.method == 'GET':
        if not current_user.is_sql:
            abort(403)

        return render_template('sql.html', seed=random.randint(0, 10 ** 9), title='Sql editor')

    elif request.method == 'POST':
        if not current_user.is_sql:
            return json.dumps({
                'status': 'denied',
                'keys': [],
                'data': []
            })

        json_data = request.get_json(force=True)
        result_proxy = db.engine.execute(json_data['request'])
        return json.dumps({
            'status': 'OK',
            'keys': result_proxy.keys(),
            'data': [row.items() for row in result_proxy.fetchall()]
        })
    else:
        abort(501)

