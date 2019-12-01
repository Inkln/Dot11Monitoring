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
            'id': index,
            'label': '{}\n({})'.format(ap.essid, ap.ap_mac),
            'group': 'AP'
        } for index, ap in enumerate(ap_list)]

        client_list = self._db.session.query(Client).filter_by(workspace=workspace).all()
        client_nodes = [{
            'id': index + len(ap_nodes),
            'label': '{}\n({})'.format(client.client_mac, client.mac_vendor),
            'group': 'Client'
        } for index, client in enumerate(client_list)]

        result_nodes = ap_nodes + client_nodes


        mac_to_id = {}
        id_to_mac = {}
        for index, ap in enumerate(ap_list):
            mac_to_id[ap.ap_mac] = index
            id_to_mac[index] = ap.ap_mac

        for index, client in enumerate(client_list):
            mac_to_id[client.client_mac] = index + len(ap_list)
            id_to_mac[index + len(ap_list)] = client.client_mac

        result_edges = []

        transfer_list = self._db.session.query(DataTransfer).filter_by(workspace=workspace).all()
        for transfer in transfer_list:
            result_edges.append({
                'from': mac_to_id[transfer.ap_mac],
                'to': mac_to_id[transfer.client_mac],
                'value': transfer.bytes
            })

        for ap1, ap2 in itertools.combinations(ap_list, 2):
            if ap1.essid == ap2.essid:
                result_edges.append({
                    'from': mac_to_id[ap1.ap_mac],
                    'to': mac_to_id[ap2.ap_mac],
                    'dashes': True,
                    'value': 1
                })

        result = {
            'nodes': result_nodes,
            'edges': result_edges
        }

        return result
    
    def json(self, workspace: str) -> str:
        return json.dumps(self.get(workspace))
