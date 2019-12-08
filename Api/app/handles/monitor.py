import itertools
import random
import json
import functools
import operator
from ...app import app, db
from ...app import graph_builder
from ..models import Ap
from flask import render_template, redirect, flash, abort, request
from flask_login import login_required, current_user

from ..utils.graph_builder import GraphBuilder

@app.route('/monitor', methods=['GET'])
#@login_required
def monitor():
    if not current_user.is_viewer:
        flash('You aren\'t viewer')
        return redirect('/main_page', 'Permissions denied')

    return render_template('monitor.html', seed=random.randint(1, 10000000))


@app.route('/get_graph', methods=['POST'])
def get_graph():
    if not current_user.is_viewer or not current_user.is_authorized:
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
def get_workspaces():
    workspaces = db.session.query(Ap.workspace).distinct().order_by(Ap.workspace).all()
    workspaces = functools.reduce(operator.add, map(list, workspaces), [])
    return json.dumps({
        'status': 'ok',
        'data': workspaces
    })
