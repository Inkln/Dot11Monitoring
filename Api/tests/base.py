import os
import sys
import requests

import pytest

TESTDIR = os.path.dirname(__file__)


@pytest.fixture(scope='function')
def get_app_and_client():
    try:
        from ..app import app, db
    except Exception:
        from app import app, db

    app.config['TESTING'] = True
    app.config['CSRF_ENABLED'] = False
    app.config['ADMIN_PASSWORD'] = 'admin_password'

    db.create_all()

    client = app.test_client(use_cookies=True)

    return app, client


def test_base(get_app_and_client):
    app, client = get_app_and_client
    assert 1 == 1
