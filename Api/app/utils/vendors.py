#!/usr/bin/python3
import re
import os
import json
import requests
from pprint import pprint

BASE_DIR = os.path.dirname(__file__)


class OfflineVendorsParser:
    def __init__(self, filename=None):
        if filename is None:
            filename = os.path.join(BASE_DIR, "mac.txt")

        text = open(filename, "r", encoding="utf-8").read().lower()

        reg = re.compile("([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}).*\(hex\)\s+(.*)")

        self.dict = {i.group(1).replace("-", ":").encode("utf-8"): i.group(2) for i in reg.finditer(text)}

    def get_vendor_info(self, mac: str):
        prefix = mac.encode()[:8]

        if prefix in self.dict:
            return self.dict[prefix]

        else:
            return "unknown"

    def get_vendor_info_for_list(self, mac_list: list):
        return list(map(self.get_vendor_info, mac_list))
