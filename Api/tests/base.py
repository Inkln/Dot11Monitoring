import os
import sys
import requests

from typing import Tuple, List

try:
    from ..app.models import *
except Exception:
    from app.models import *

from flask import Flask
from flask.testing import FlaskClient
import pytest

TESTDIR = os.path.dirname(__file__)


@pytest.fixture(scope='function')
def get_app_and_client() -> Tuple[Flask, FlaskClient]:

    try:
        from ..app import app, db, insert_admin_into_db
    except Exception:
        from app import app, db, insert_admin_into_db

    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['ADMIN_PASSWORD'] = 'admin_password'

    db.create_all()

    client = app.test_client(use_cookies=True)

    return app, client


def test_index_page(get_app_and_client):
    app, client = get_app_and_client
    response = client.get('/')
    assert response.status == '200 OK'
    assert response.data.decode('utf-8').find('Login') >= 0
    assert response.data.decode('utf-8').find('Register') >= 0


def test_login(get_app_and_client):
    app, client = get_app_and_client
    response = client.post('/login', data={'username': 'admin', 'password': 'admin_password'})
    assert response.status == '303 SEE OTHER'
