import pymongo
import re

import operator
import functools

import api_connector

class PairStorage:

    def __init__(self, db_name: str, first_key: str, second_key: str):
        self.db_name = db_name
        self.first_key = first_key
        self.second_key = second_key

        self.client = pymongo.MongoClient('localhost', 27017)
        self.db = self.client[db_name]

        self.collection = self.db['from-{}-to-{}'.format(first_key, second_key)]

        # unique indexing
        if self.collection.index_information() == {}:
            self.collection.create_index(
                [(self.first_key, pymongo.ASCENDING), (self.second_key, pymongo.ASCENDING)],
                unique=False
            )

    def insert_pair(self, pair: tuple):
        '''
        :param pair: pair of objects (object, object)
        '''
        try:
            self.collection.insert_one({ self.first_key : pair[0], self.second_key : pair[1] })
        except:
            pass

    def insert_pairs(self, data: list):
        '''
        :param data: list of pairs to insert [(,), (,) ...]
        '''

        documents = [{self.first_key : pair[0], self.second_key : pair[1]}
                                for pair in data]

        for document in documents:
            try:
                self.collection.insert_one(document)
            except:
                pass

    def select_by_first(self, first_value: any) -> list:
        request_result = self.collection.find({self.first_key : first_value})
        return [ (pair[self.first_key], pair[self.second_key]) for pair in request_result ]

    def select_by_second(self, second_value: any) -> list:
        request_result = self.collection.find({self.second_key : second_value})
        return [(pair[self.first_key], pair[self.second_key]) for pair in request_result]

    def select_all(self) -> list:
        request_result = self.collection.find()
        return [(pair[self.first_key], pair[self.second_key]) for pair in request_result]

    def check_for_existence(self, first_value: any, second_value: any) -> bool:
        request_result = self.collection.find_one(
            { self.first_key : first_value, self.second_key : second_value }
        )
        return not request_result is None

    def drop(self):
        self.collection.drop()


class ApStorage(PairStorage):
    '''
    list of ('ap_mac', 'ap_essid')
    '''
    def __init__(self):
        super().__init__('mac_storage', 'ap_mac', 'ap_essid')

    def select_by_ap_mac(self, ap_mac: bytes):
        return self.select_by_first(ap_mac)

    def select_by_ap_essid(self, ap_essid: bytes):
        return self.select_by_second(ap_essid)


class ClientStorage(PairStorage):
    '''
    list of ('ap_mac', 'client_mac')
    '''
    def __init__(self):
        super().__init__('mac_storage', 'ap_mac', 'client_mac')

    def select_by_ap_mac(self, ap_mac: bytes):
        return self.select_by_first(ap_mac)

    def select_by_ap_essid(self, ap_essid: bytes):
        return self.select_by_second(ap_essid)