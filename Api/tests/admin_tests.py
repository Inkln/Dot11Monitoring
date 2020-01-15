import os
import sys
import requests

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


class TestAdmin(TestCase):
    def create_app(self):
        try:
            from ..app import app, db, insert_admin_into_db
        except Exception:
            from app import app, db, insert_admin_into_db
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['ADMIN_PASSWORD'] = 'admin_password'
        # db.create_all()
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

    def test_1(self):
        """
        enter admin page
        """
        self.login('admin', 'admin_password')
        response = self.client.get('/admin')
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_2(self):
        """
        attempt to enter the admin page as an unregistered user
        """
        response = self.client.get('/admin')
        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/index?next=%2Fadmin')

    def test_3(self):
        """
        attempt to enter the admin page as a common user
        """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        response = self.client.get('/admin')
        assert response.status == '403 FORBIDDEN'
        assert response.status_code == 403

    def test_4(self):
        """
        POST incorrect data
        """
        self.login('admin', 'admin_password')
        response = self.client.post('/admin', data={'lol':'kek'})
        assert response.status == '400 BAD REQUEST'
        assert response.status_code == 400

    def test_5(self):
        """
        get user some right by admin
        """
        username, password = self.register_random_client()
        self.login('admin', 'admin_password')
        db = self.create_db()
        user = db.session.query(User).filter(User.username==username)[0]
        user_id = user.id
        self.client.get('/admin')
        response = self.client.post('/admin', data={'id':user_id,
                                                    'username': username,
                                                    'is_viewer': True,
                                                    'is_collector': True,
                                                    'is_sql': True,
                                                    'action':"Edit and save"})

        user = db.session.query(User).filter(User.username == username)[0]
        assert user.is_viewer == True
        assert user.is_collector == True
        assert user.is_sql == True
        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/admin')

    def test_6(self):
        """
        take user some right by admin
        """
        username, password = self.register_random_client()
        self.login('admin', 'admin_password')
        db = self.create_db()
        user = db.session.query(User).filter(User.username==username)[0]
        user_id = user.id
        self.client.get('/admin')
        self.client.post('/admin', data={'id':user_id,
                                         'username': username,
                                         'is_viewer': True,
                                         'is_collector': True,
                                         'is_sql': True,
                                         'action':"Edit and save"})

        response = self.client.post('/admin', data={'id': user_id,
                                                    'username': username,
                                                    'is_viewer': False,
                                                    'is_collector': False,
                                                    'is_sql': False,
                                                    'action': "Edit and save"})

        user = db.session.query(User).filter(User.username == username)[0]
        assert user.is_viewer == False
        assert user.is_collector == False
        assert user.is_sql == False
        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/admin')

    def test_7(self):
        """
        get user admin right by admin
        """
        username, password = self.register_random_client()
        self.login('admin', 'admin_password')
        db = self.create_db()
        user = db.session.query(User).filter(User.username==username)[0]
        user_id = user.id
        self.client.get('/admin')
        self.client.post('/admin', data={'id':user_id,
                                         'username': username,
                                         'is_admin': True,
                                         'action':"Edit and save"})

        user = db.session.query(User).filter(User.username == username)[0]
        self.client.get('/logout')
        self.login(username, password)
        response = self.client.get('/admin')
        assert user.is_admin == True
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_8(self):
        """
        take user admin right by admin
        """
        username, password = self.register_random_client()
        self.login('admin', 'admin_password')
        db = self.create_db()
        user = db.session.query(User).filter(User.username==username)[0]
        user_id = user.id
        self.client.get('/admin')
        self.client.post('/admin', data={'id':user_id,
                                         'username': username,
                                         'is_admin': True,
                                         'action':"Edit and save"})

        self.client.post('/admin', data={'id': user_id,
                                         'username': username,
                                         'is_admin': False,
                                         'action': "Edit and save"})
        user = db.session.query(User).filter(User.username == username)[0]
        self.client.get('/logout')
        self.login(username, password)
        response = self.client.get('/admin')
        assert user.is_admin == False
        assert response.status == '403 FORBIDDEN'
        assert response.status_code == 403

    def test_9(self):
        """
        change user password by admin
        """
        username, password = self.register_random_client()
        new_password = get_random_string()
        self.login('admin', 'admin_password')
        db = self.create_db()
        user = db.session.query(User).filter(User.username==username)[0]
        user_id = user.id
        self.client.get('/admin')
        self.client.post('/admin', data={'id':user_id,
                                         'username': username,
                                         'password': new_password,
                                         'action':"Edit and save"})

        self.client.get('/logout')
        response = self.login(username, new_password)
        assert response.status == '303 SEE OTHER'
        assert response.status_code == 303
        self.assertRedirects(response, '/main_page')

    def test_delete_user(self):
        """
        delete user by admin
        """
        username, password = self.register_random_client()
        self.login('admin', 'admin_password')
        db = self.create_db()
        user = db.session.query(User).filter(User.username==username)[0]
        user_id = user.id
        self.client.get('/admin')
        response = self.client.post('/admin', data={'id':user_id,
                                                    'username': username,
                                                    'is_viewer': True,
                                                    'action':"Delete"})

        n_user = db.session.query(User).filter(User.username == username).count()
        assert n_user == 0
        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/admin')