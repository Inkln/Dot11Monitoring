import os
import sys
import typing
import itertools
import json
import urllib.request
import time

import requests

import scapy
import scapy.all

import queue

class CallbackEvent:
    def to_mongo_json(self) -> str:
        raise NotImplementedError()



class ConnectionEvent(CallbackEvent):
    def __init__(self, client_mac: str, ap_mac: str):
        self.client_mac_ = client_mac
        self.ap_mac_ = ap_mac
        self.init_time_ = time.time()

    def to_mongo_format(self) -> str:
        result = {'ap_mac': self.ap_mac_, 'client_mac': self.client_mac_, 'init_time': self.init_time_}





