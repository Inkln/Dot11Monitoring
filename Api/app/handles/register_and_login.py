import json

from flask import request, abort, config, redirect

from ..models import User
from ...app import app, db


@app.route('/register/<string:login><string:password><string:email>', methods=['POST'])
def register(login, password, email):
    exists = db.session.query(User).filter_by(username=login).first()
    if exists is not None:
        return 'user already exists'

