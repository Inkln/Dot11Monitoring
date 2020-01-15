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


class TestSQL(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['ADMIN_PASSWORD'] = 'admin_password'
        return app

    def create_db(self):
        db.create_all()
        return db

    def register_client(self, username, password, repeat_password=None):
        if repeat_password is None:
            repeat_password = password
        return self.client.post('/register', data={'username': username,
                                             'password': password,
                                             'repeat_password': repeat_password})

    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password})

    def register_random_client(self):
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
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

    def test_get_1(self):
        """
        attempt to enter the admin page as an unregistered user
        """
        response = self.client.get('/sql')
        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/index?next=%2Fsql')

    def test_get_2(self):
        """
        attempt to enter the admin page as an common user
        """
        self.register_random_client()
        response = self.client.get('/sql')
        assert response.status == '403 FORBIDDEN'
        assert response.status_code == 403

    def test_get_3(self):
        """
        attempt to enter the admin page as an admin
        """
        self.login('admin', 'admin_password')
        response = self.client.get('/sql')
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_get_4(self):
        """
        attempt to enter the admin page as a privileged user
        """
        username, password = self.register_random_client()
        self.set_right_to_user(username, is_sql=True)
        self.login(username, password)
        response = self.client.get('/sql')
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_post_1(self):
        """
        simple sql query
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/sql', data=json.dumps({'request': 'select 1'}))
        assert json.loads(response.data)['status'] == 'OK'
        assert json.loads(response.data)['data'][0][0][1] == 1
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_post_2(self):
        """
        wrong sql query
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/sql', data=json.dumps({'request': 'select lol kek'}))
        assert json.loads(response.data)['status'] == 'error'
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_post_3(self):
        """
        select from AP
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/sql', data=json.dumps({'request': 'select * from AP'}))
        keys = set(("id", "ap_mac", "workspace", "mac_vendor", "essid", "channel", "privacy", "comment"))
        print('AP')
        print(response.data)
        print('='*10)
        assert json.loads(response.data)['status'] == 'OK'
        assert set(json.loads(response.data)['keys']) == keys
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_post_4(self):
        """
        simple sql query
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/sql', data=json.dumps({'request': 'select * from AUTH'}))
        keys = set(("id", "ap_mac", "client_mac", "workspace", "stage", "tries"))
        print('AUTH')
        print(response.data)
        print('=' * 10)
        assert json.loads(response.data)['status'] == 'OK'
        assert set(json.loads(response.data)['keys']) == keys
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_post_5(self):
        """
        simple sql query
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/sql', data=json.dumps({'request': 'select * from CLIENT'}))
        print('CLIENT')
        print(response.data)
        print('=' * 10)
        keys = set(("id", "client_mac", "workspace", "mac_vendor", "comment"))
        assert json.loads(response.data)['status'] == 'OK'
        assert set(json.loads(response.data)['keys']) == keys
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_post_6(self):
        """
        simple sql query
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/sql', data=json.dumps({'request': 'select * from DATA_TRANSFER'}))
        # print('DATA_TRANSFER')
        # print(response.data)
        # print('=' * 10)
        keys = set(("id", "ap_mac", "client_mac", "workspace", "bytes"))
        assert json.loads(response.data)['status'] == 'OK'
        assert set(json.loads(response.data)['keys']) == keys
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_post_7(self):
        """
        wrong data format
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/sql', data='lol kek')
        assert response.status == '400 BAD REQUEST'
        assert response.status_code == 400

    def test_post_8(self):
        """
        private table
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/sql', data=json.dumps({'request': 'select * from private.users'}))
        assert json.loads(response.data)['status'] == 'error'
        assert json.loads(response.data)['message'] == "database server rejected your request"
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_post_9(self):
        """
        use complicated sql query
        """
        pass
        # print('0' * 20)
        # print('0' * 20)
        # print('0' * 20)
        # self.register_random_client()
        # self.register_random_client()
        # self.login('admin', 'admin_password')
        # response = self.client.post('/sql', data=json.dumps({'request': 'select * from AP'}))
        # print('AP')
        # print(response.data)
        # print('=' * 10)
        # response = self.client.post('/sql', data=json.dumps({'request': 'select * from CLIENT'}))
        # print('CLIENT')
        # print(response.data)
        # print('=' * 10)
        # response = self.client.post('/sql', data=json.dumps({'request': 'select * from AUTH'}))
        # print('AUTH')
        # print(response.data)
        # print('=' * 10)
        # response = self.client.post('/sql', data=json.dumps({'request': 'select * from DATA_TRANSFER'}))
        # print('DATA_TRANSFER')
        # print(response.data)
        # print('=' * 10)

    def test_add_results(self):
        """
        use add_result
        """
        with open('./tests/add_result.json') as F:
            results = F.read()
        self.login('admin', 'admin_password')
        response = self.client.post('/add_result', json=json.loads(results))
        assert response.status == '200 OK'
        assert response.status_code == 200
        response = self.client.post('/sql', data=json.dumps({'request': 'select * from AP'}))
        assert len(json.loads(response.data)['data']) >= 1
        response = self.client.post('/sql', data=json.dumps({'request': 'select * from CLIENT'}))
        assert len(json.loads(response.data)['data']) >= 1
        response = self.client.post('/sql', data=json.dumps({'request': 'select * from AUTH'}))
        assert len(json.loads(response.data)['data']) >= 1
        response = self.client.post('/sql', data=json.dumps({'request': 'select * from DATA_TRANSFER'}))
        assert len(json.loads(response.data)['data']) >= 1





