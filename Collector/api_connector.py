import os
import requests
import asyncio
import urllib
import json
import time
import queue
import typing
import hashlib
import io


class ApiConnector:

    def __init__(self, host: str, token: str):
        self.host_ = host
        self.address_= self.host_ + '/collector_api'
        self.session_ = requests.Session()
        data = {
            'token': token
        }
        response = self.session_.post(self.address_, json=data)
        if response.status_code != requests.codes.ok:
            raise RuntimeError('Server returned [{}] code'.format(response.status_code))


    def insert_data(self, data: typing.List[typing.Any]) -> None:
        data = {
            'command': 'insert_data',
            'data': data,
        }

        response = self.session_.post(self.address_, json=data)
        if response.status_code != requests.status_codes.ok:
            raise RuntimeError('[insert_data] Server returned [{}] code'.format(response.status_code))