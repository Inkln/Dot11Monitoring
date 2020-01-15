try:
    from ..collection_service import *
except Exception:
    from collection_service import *

import os
import sys
import json
import pytest
import base64

import scapy
import scapy.packet
import scapy.utils
import scapy.all
import scapy.layers.dot11


@pytest.fixture(scope="session")
def get_sample_pcapng():
    return scapy.all.rdpcap("./tests/sample.pcapng")


@pytest.fixture(scope="session")
def get_eapol_handshake():
    return [
        [1, b'AAAgAK5AAKAgCACgIAgAABACgAmgANgAZAAAAAAAAAGIAjoB2M46'
            b'jI5CdHD9VFCOdHD9VFCOAAAHAKqqAwAAAIiOAgMAXwIAigAQAAAAA'
            b'AAAAAEVWPY2B2sHyo3LO4NGJ7UI8p/T1YOsVoeltvyyeN5uLAAAAA'
            b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            b'AAAAAAAAAbCq6Dg=='],
        [2, b'AAAgAK5AAKAgCACgIAgAABACgAmgANQAZAAAAAAAAAGIAToBdHD9V'
            b'FCO2M46jI5CdHD9VFCOAAAGAKqqAwAAAIiOAQMAdQIBCgAAAAAAAA'
            b'AAAAGCbCGVSXKRm0GDLZW7s1FWAjP+a6sOIj5C+W/j4nemTwAAAAA'
            b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoSYapc7rbRvBKyBS'
            b'3jNxAAAWMBQBAAAPrAIBAAAPrAQBAAAPrAIAAHrysJw='],
        [3, b'AAAgAK5AAKAgCACgIAgAABACgAmgANQAZAAAAAAAAAGIAjoB2M46j'
            b'I5C1G4OlZLm1G4OlZLmEAAGAKqqAwAAAIiOAgMArwITygAQAAAAAA'
            b'AAAAL8IADROL+p7rmgJ6vnwrEs7MNbpqFpojlSfncebmWILQAAAAA'
            b'AAAAAAAAAAAAAAAA1LgUAAAAAAAAAAAAAAAAAhUXtaf/d4lbTvVoX'
            b'3opvIgBQq4c+xe0XJPzmj6Eb3yuD73IuNQFEchkfYCBngHKrY6io3'
            b'U0peyKwdS8mE8SurgDdUaDNHoEQQpNSJNJwzYQ/Yt8K0jHsRoL5zW'
            b'Zn+1ASJiXSpugE'],
        [4, b'AAAgAK5AAKAgCACgIAgAABACgAmgANQAZAAAAAAAAAGIAToB1G4Ol'
            b'ZLm2M46jI5C1G4OlZLmEAAGAKqqAwAAAIiOAQMAXwIDCgAAAAAAAA'
            b'AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU0m97Qkf7xf2gol1'
            b'RE/MugAAJMy/zA=='],
    ]


def test_eapol_encoder(get_eapol_handshake):
    for stage, packet_encoded in get_eapol_handshake:
        packet = scapy.layers.dot11.RadioTap(_pkt=base64.b64decode(packet_encoded))
        header = EAPOLPayloadHeader(packet[scapy.packet.Raw].load)
        assert header.get_stage() == stage


def test_decoder(get_sample_pcapng):
    pcap = get_sample_pcapng
    assert Decoder.decode_pcap(pcap).get() == {
        'visible_aps': {'2c:56:dc:45:f7:24': {'essid': 'GST', 'privacy': 'wpa2', 'channel': 2432},
                        '2c:fd:a1:68:30:a4': {'essid': 'Nescafe228*', 'privacy': 'wep', 'channel': 2432},
                        '60:e3:27:85:8d:8c': {'essid': 'TP-LINK_8D8C', 'privacy': 'wpa2', 'channel': 2432},
                        '74:70:fd:54:50:8e': {'essid': 'wpa test', 'privacy': 'wpa2', 'channel': 2432},
                        '04:95:e6:47:07:28': {'essid': 'BRAYEST', 'privacy': 'wpa', 'channel': 2432},
                        'd4:6e:0e:95:92:e6': {'essid': 'LAGMAN', 'privacy': 'wpa2', 'channel': 2432},
                        'cc:7b:35:8a:e4:98': {'essid': 'MGTS_GPON_8812', 'privacy': 'wpa2', 'channel': 2432},
                        '40:31:3c:03:a3:05': {'essid': 'NASH_BRATAN_FUNCAN', 'privacy': 'wep', 'channel': 2432},
                        '14:dd:a9:cd:b3:70': {'essid': 'ZuZu', 'privacy': 'wpa2', 'channel': 2432},
                        'ec:43:f6:00:3c:a8': {'essid': 'penek', 'privacy': 'wep', 'channel': 2432}},
        'visible_clients': {'d8:bb:2c:26:59:ad': {}, 'd8:ce:3a:8c:8e:42': {}, '48:d2:24:e0:a6:f5': {}},
        'client_ap_data_transfer': [{'ap': '2c:56:dc:45:f7:24', 'client': 'd8:bb:2c:26:59:ad', 'bytes': 2473},
                                    {'ap': 'd4:6e:0e:95:92:e6', 'client': 'd8:ce:3a:8c:8e:42', 'bytes': 34501},
                                    {'ap': 'd4:6e:0e:95:92:e6', 'client': '48:d2:24:e0:a6:f5', 'bytes': 5167939}],
        'client_authorised': [{'ap': '74:70:fd:54:50:8e', 'client': 'd8:ce:3a:8c:8e:42', 'stage': 2, 'tries': 4},
                              {'ap': 'd4:6e:0e:95:92:e6', 'client': 'd8:ce:3a:8c:8e:42', 'stage': 4, 'tries': 2}]}
