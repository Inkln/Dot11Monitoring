import os
import json
import sys
import typing
import random
import functools
import itertools

from flask_login import current_user

from ...app import db
from ...app.models import Ap, Client, DataTransfer, Auth


class GraphBuilder:

    def __init__(self, db=db):
        self._db = db

    def get(self, workspace: str):
        ap_list = self._db.session.query(Ap).filter_by(workspace=workspace).all()
        ap_nodes = [{
            'id': ap.ap_mac,
            'label': '{}\n({})'.format(ap.ap_mac, ap.essid),
            'group': 'ap'
        } for ap in ap_list]

        client_list = self._db.session.query(Client).filter_by(workspace=workspace).all()
        client_nodes = [{
            'id': client.client_mac,
            'label': '{}\n({})'.format(client.client_mac, client.mac_vendor),
            'group': 'client'
        } for client in client_list]
        result_nodes = ap_nodes + client_nodes

        result_edges = []

        transfer_list = self._db.session.query(DataTransfer).filter_by(workspace=workspace).all()
        for transfer in transfer_list:
            result_edges.append({
                'id': transfer.ap_mac + transfer.client_mac,
                'to': transfer.ap_mac,
                'from': transfer.client_mac,
                'value': transfer.bytes,
                'title': '{}KB'.format(transfer.bytes // 1024)
            })

        for ap1, ap2 in itertools.combinations(ap_list, 2):
            if ap1.essid == ap2.essid:
                result_edges.append({
                    'id': min(ap1.ap_mac, ap2.ap_mac) + max(ap1.ap_mac, ap2.ap_mac),
                    'from': ap1.ap_mac,
                    'to': ap2.ap_mac,
                    'dashes': True,
                    'value': 1,
                    'length': 2
                })

        result = {
            'nodes': result_nodes,
            'edges': result_edges
        }

        return result
    
    def json(self, workspace: str) -> str:
        return json.dumps(self.get(workspace))
