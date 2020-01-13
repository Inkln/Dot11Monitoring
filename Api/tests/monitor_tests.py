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


class TestMonitor(TestCase):
    # ToDo test for privileged user
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

    def test_monitor_1(self):
        """
        non-privileged user goes to page "monitor"
        """
        self.register_random_client()
        response = self.client.get('/monitor')
        assert response.status == '403 FORBIDDEN'
        assert response.status_code == 403

    def test_monitor_2(self):
        """
        admin goes to page "monitor"
        """
        self.login('admin', 'admin_password')
        response = self.client.get('/monitor')
        assert response.status == '200 OK'
        assert response.status_code == 200

    def test_graph_1(self):
        """
        non-privileged user goes to page "get_graph"
        """
        self.register_random_client()
        response = self.client.get('/get_graph')
        assert response.status == '200 OK'
        assert response.status_code == 200
        assert 'denied' in response.data.decode('utf-8')

    def test_graph_2(self):
        """
        admin goes to page "get_graph"
        """
        self.login('admin', 'admin_password')
        response = self.client.get('/get_graph')
        assert response.status == '200 OK'
        assert response.status_code == 200
        assert 'ok' in response.data.decode('utf-8')

    def test_workspaces_1(self):
        """
        non-privileged user goes to page "get_workspaces"
        """
        self.register_random_client()
        response = self.client.get('/get_workspaces')
        assert response.status == '200 OK'
        assert response.status_code == 200
        assert 'denied' in response.data.decode('utf-8')

    def test_workspaces_2(self):
        """
        admin goes to page "get_workspaces"
        """
        self.login('admin', 'admin_password')
        response = self.client.get('/get_workspaces')
        assert response.status == '200 OK'
        assert response.status_code == 200
        assert 'ok' in response.data.decode('utf-8')
