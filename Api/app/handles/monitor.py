import itertools
import random
import json
import functools
import operator

try:
    from ...app import app, db
    from ...app import graph_builder
    from ..models import Ap
except:
    from app import app, db
    from app import graph_builder
    from app.models import Ap
from flask import render_template, redirect, flash, abort, request
from flask_login import login_required, current_user

@app.route('/monitor', methods=['GET'])
@login_required
def monitor():
    if not current_user.is_viewer:
        flash('You aren\'t viewer')
        abort(403)

    return render_template('monitor.html', seed=random.randint(1, 10000000), title='Monitor')


@app.route('/get_graph', methods=['POST'])
@login_required
def get_graph():
    if not current_user.is_viewer:
        return json.dumps({
            'status': 'denied'
        })
    json_data = request.get_json(force=True)
    data = graph_builder.get(workspace=json_data['workspace'])

    return json.dumps({
        'status': 'ok',
        'data': data
    })

@app.route('/get_workspaces', methods=['POST'])
@login_required
def get_workspaces():
    if not current_user.is_viewer:
        return json.dumps({
            'status': 'denied'
        })
    workspaces = db.session.query(Ap.workspace).distinct().order_by(Ap.workspace).all()
    workspaces = functools.reduce(operator.add, map(list, workspaces), [])
    return json.dumps({
        'status': 'ok',
        'data': workspaces
    })
