import os
import sys
import requests
import json

from typing import Tuple, List

from flask import Flask
from flask.testing import FlaskClient
import pytest
from flask_testing import TestCase, LiveServerTestCase
import flask_testing
try:
    from ..models import User, Ap, Auth, Client, DataTransfer
    from ...app import app, db
except Exception:
    from app.models import User, Ap, Auth, Client, DataTransfer
    from app import app, db

TESTDIR = os.path.dirname(__file__)

import random
import string


def get_random_string(string_length=15):
    """
    Generate a random string of fixed length
    :param string_length: int:  string length
    :return: str: random string
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(string_length))

class TestGather(TestCase):
    def create_app(self):
        try:
            from ..app import app, db, insert_admin_into_db
        except Exception:
            from app import app, db, insert_admin_into_db
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['ADMIN_PASSWORD'] = 'admin_password'
        return app

    def create_db(self):
        try:
            from ..app import db, insert_admin_into_db
        except Exception:
            from app import db, insert_admin_into_db
        db.create_all()
        return db

    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password})

    def register_client(self, username, password, repeat_password=None):
        if repeat_password is None:
            repeat_password = password
        return self.client.post('/register', data={'username': username,
                                             'password': password,
                                             'repeat_password': repeat_password})

    def register_random_client(self):
        random_username = get_random_string()
        random_password = get_random_string()
        response = self.register_client(random_username, random_password)
        self.client.get('/logout')
        return random_username, random_password

    def set_right_to_user(self, username, is_viewer=False, is_collector=False, is_sql=False):
        self.client.get('/logout')
        self.login('admin', 'admin_password')
        db = self.create_db()
        user = db.session.query(User).filter(User.username == username)[0]
        user_id = user.id
        self.client.get('/admin')
        self.client.post('/admin', data={'id': user_id,
                                         'username': username,
                                         'is_viewer': is_viewer,
                                         'is_collector': is_collector,
                                         'is_sql': is_sql,
                                         'action': "Edit and save"})
        self.client.get('/logout')

    def test_gather_1(self):
        """
        attempt to post result by an unregistered user
        """
        with open('./tests/add_result.json') as F:
            results = F.read()
        response = self.client.post('/add_result', json=json.loads(results))
        assert response.status == '302 FOUND'
        assert response.status_code == 302

    def test_gather_2(self):
        """
        non-privileged try to post results
        """
        with open('./tests/add_result.json') as F:
            results = F.read()
        self.register_random_client()
        response = self.client.post('/add_result', json=json.loads(results))
        assert response.status == '302 FOUND'
        assert response.status_code == 302

    def test_gather_3(self):
        """
        privileged user post results
        """
        with open('./tests/add_result.json') as F:
            results = F.read()
        username, password = self.register_random_client()
        self.set_right_to_user(username, is_collector=True)
        self.login(username, password)
        response = self.client.post('/add_result', json=json.loads(results))
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_gather_4(self):
        """
        post result by admin
        """
        with open('./tests/add_result.json') as F:
            results = F.read()
        self.login('admin', 'admin_password')
        response = self.client.post('/add_result', json=json.loads(results))
        assert response.data.decode('utf-8') == 'OK'
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_gather_5(self):
        """
        post incorrect data
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/add_result', json='lol kek')
        assert response.status == '406 NOT ACCEPTABLE'
        assert response.status_code == 406
