import os
import sys
import requests

from typing import Tuple, List

from flask import Flask
from flask.testing import FlaskClient
import pytest
from flask_testing import TestCase, LiveServerTestCase
import flask_testing

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


class TestLogin(TestCase):
    def create_app(self):
        try:
            from ..app import app, db, insert_admin_into_db
        except Exception:
            from app import app, db, insert_admin_into_db
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['ADMIN_PASSWORD'] = 'admin_password'
        return app

    def register_client(self, username, password, repeat_password=None):
        if repeat_password is None:
            repeat_password = password
        return self.client.post('/register', data={'username': username,
                                             'password': password,
                                             'repeat_password': repeat_password})

    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password})

    def test_login_1(self):
        """
        log in as a registered user
        """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        self.client.get('/logout')
        response = self.login(random_username, random_password)
        assert response.status == '303 SEE OTHER'
        assert response.status_code == 303
        self.assertRedirects(response, '/main_page')

    def test_login_2(self):
        """
        log in as a an not registered user
        """
        random_username = get_random_string()
        random_password = get_random_string()
        response = self.login(random_username, random_password)

        assert response.status == '304 NOT MODIFIED'
        assert response.status_code == 304

    def test_login_3(self):
        """
        try to use incorrect password
        """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        self.client.get('/logout')
        random_password = get_random_string()
        response = self.login(random_username, random_password)
        assert response.status == '304 NOT MODIFIED'
        assert response.status_code == 304

    def test_login_4(self):
        """
        try to use incorrect username
        """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        self.client.get('/logout')
        random_username = get_random_string()
        response = self.login(random_username, random_password)
        assert response.status == '304 NOT MODIFIED'
        assert response.status_code == 304

    def test_login_5(self):
        """
        attempt to login with incorrect data(extra line)
        """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        response = self.client.post('/login', data={'username': random_username,
                                                    'password': random_password,
                                                    'add_line': random_password})
        assert response.status == '303 SEE OTHER'
        assert response.status_code == 303
        self.assertRedirects(response, '/main_page')

    def test_login_6(self):
        """
        attempt to login with incorrect data(change one line)
         """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        response = self.client.post('/login', data={'username': random_username,
                                                    'password_2': random_password})
        assert response.status == '304 NOT MODIFIED'
        assert response.status_code == 304

    def test_login_7(self):
        """
        attempt to login with incorrect data(repeat one line)
         """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        response = self.client.post('/login', data={'username': random_username,
                                                    'password': random_password,
                                                    'password': random_password})
        assert response.status == '303 SEE OTHER'
        assert response.status_code == 303
        self.assertRedirects(response, '/main_page')

##############################
#They don't seem to be needed#
##############################


class TestAdminLogin(TestCase):
    def create_app(self):
        try:
            from ..app import app, db, insert_admin_into_db
        except Exception:
            from app import app, db, insert_admin_into_db
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['ADMIN_PASSWORD'] = 'admin_password'
        return app

    def test_login(self):
        """
        login as an admin
        """
        response = self.client.post('/login', data={'username': 'admin', 'password': 'admin_password'})
        assert response.status == '303 SEE OTHER'
        assert response.status_code == 303
        self.assertRedirects(response, '/main_page')

    def test_login_fall(self):
        """
        wrong password for admin account
        """
        random_password = get_random_string()
        response = self.client.post('/login', data={'username': 'admin', 'password': random_password})
        assert response.status == '304 NOT MODIFIED'
        assert response.status_code == 304

    def test_login_fall_2(self):
        """
        wrong login and correct password for admin account
        """
        random_username = get_random_string()
        response = self.client.post('/login', data={'username': random_username, 'password':'admin_password'})
        assert response.status == '304 NOT MODIFIED'
        assert response.status_code == 304


class TestRegistration(TestCase):
    def create_app(self):
        try:
            from ..app import app, db, insert_admin_into_db
        except Exception:
            from app import app, db, insert_admin_into_db
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['ADMIN_PASSWORD'] = 'admin_password'
        return app

    def register_client(self, username, password, repeat_password=None):
        if repeat_password is None:
            repeat_password = password
        return self.client.post('/register', data={'username': username,
                                             'password': password,
                                             'repeat_password': repeat_password})

    def test_register_1(self):
        """
        registration
        """
        random_username = get_random_string()
        random_password = get_random_string()
        response = self.register_client(random_username, random_password)

        assert response.status == '303 SEE OTHER'
        assert response.status_code == 303
        self.assertRedirects(response, '/main_page')

    def test_register_2(self):
        """
        attempt to re-register
        """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        response = self.register_client(random_username, random_password)
        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/main_page')

    def test_register_3(self):
        """
        passwords do not match
        """
        random_username = get_random_string()
        random_password = get_random_string()
        random_password_2 = get_random_string()
        response = self.register_client(random_username, random_password, random_password_2)

        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/index')

    def test_logout(self):
        """
        logout
        """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        response = self.client.get('/logout')

        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/index')

    def test_register_4(self):
        """
        attempt to register an existing user
        """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        self.client.get('/logout')
        response = self.register_client(random_username, random_password)

        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/index')

    def test_register_5(self):
        """
        attempt to register an existing user with new password
        """
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        self.client.get('/logout')
        random_password = get_random_string()
        response = self.register_client(random_username, random_password)

        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/index')

    def test_register_6(self):
        """
        attempt to register with incorrect data(extra line)
        """
        random_username = get_random_string()
        random_password = get_random_string()
        response = self.client.post('/register', data={'username': random_username,
                                       'password': random_password,
                                       'repeat_password': random_password, 'add_line': random_password})
        assert response.status == '303 SEE OTHER'
        assert response.status_code == 303
        self.assertRedirects(response, '/main_page')

    def test_register_7(self):
        """
        attempt to register with incorrect data(change one line)
         """
        random_username = get_random_string()
        random_password = get_random_string()
        response = self.client.post('/register', data={'username': random_username,
                                                       'password': random_password,
                                                       'password_2': random_password})
        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/index')

    def test_register_8(self):
        """
        attempt to register with incorrect data(repeat one line)
         """
        random_username = get_random_string()
        random_password = get_random_string()
        response = self.client.post('/register', data={'username': random_username,
                                                       'password': random_password,
                                                       'repeat_password': random_password,
                                                       'repeat_password': random_password})
        assert response.status == '303 SEE OTHER'
        assert response.status_code == 303
        self.assertRedirects(response, '/main_page')
