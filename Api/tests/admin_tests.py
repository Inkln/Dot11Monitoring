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


class TestAdmin(TestCase):
    # ToDo db tests
    def create_app(self):
        try:
            from ..app import app, db, insert_admin_into_db
        except Exception:
            from app import app, db, insert_admin_into_db
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['ADMIN_PASSWORD'] = 'admin_password'
        db.create_all()
        return app

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

    # def test_5(self):
    #     """
    #     delete user by admin
    #     """
    #     username, password = self.register_random_client()
    #     self.login('admin', 'admin_password')
    #     response = self.client.get('/admin')
    #     print(response.data.decode('utf-8'))
    #     print('=============')
    #     print('=============')
    #     print('=============')
    #     print('=============')
    #
    #     response = self.client.post('/admin', data={'id':1,
    #                                                 'username': username,
    #                                                 'is_viewer': True,
    #                                                 'action':"Edit and save"})
    #     print(response.status)
    #     assert response.status == '400 BAD REQUEST'
    #     assert response.status_code == 400
    #     self.assertRedirects(response, '/admin')

