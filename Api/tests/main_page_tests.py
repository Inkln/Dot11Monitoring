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


class TestMainPage(TestCase):
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

    def register_random_client(self):
        random_username = get_random_string()
        random_password = get_random_string()
        self.register_client(random_username, random_password)
        return random_username, random_password

    def test_1(self):
        """
        unauthorized user tries to enter the main page
        """
        response = self.client.get('/main_page')
        assert response.status == '302 FOUND'
        assert response.status_code == 302
        self.assertRedirects(response, '/index?next=%2Fmain_page')

    def test_2(self):
        """
        authorized user tries to enter the main page
        """
        _ = self.register_random_client()
        response = self.client.get('/main_page')
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_3(self):
        """
        admin tries to enter the main page
        """
        self.login('admin', 'admin_password')
        response = self.client.get('/main_page')
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_4(self):
        """
        try to POST
        """
        _ = self.register_random_client()
        response = self.client.post('/main_page')
        assert response.status == '405 METHOD NOT ALLOWED'
        assert response.status_code == 405
