import pprint
import json
import queue
import subprocess
import collections

import subprocess
import requests
import multiprocessing

from typing import List, Set, Tuple, Optional, Dict, Any, Union, Iterable

import scapy
import scapy.packet
import scapy.layers.dot11
import scapy.layers.eap
import scapy.utils
import scapy.all
import scapy.sendrecv

import tqdm

class ScanResult:
    def __init__(self):
        self.visible_aps = dict()
        self.visible_clients = dict()
        self.client_ap_data_transfer = list()
        self.client_authorised = list()

    def get(self) -> Dict[str, Any]:
        result = {
            'visible_aps': self.visible_aps,
            'visible_clients': self.visible_clients,
            'client_ap_data_transfer': self.client_ap_data_transfer,
            'client_authorised': self.client_authorised,
        }
        return result

    def __str__(self) -> str:
        return json.dumps(self.get(), sort_keys=True)


class ScannerEpoch:
    def __init__(self, interface: str, channel: int, timeout: int = 2):
        self.interface_ = interface
        self.channel_ = channel
        self.timeout_ = timeout
        self.result_ = []

    def _set_channel(self) -> None:
        subprocess.run(['iwconfig', self.interface_, 'channel', str(self.channel_)])

    def _push_back_cp(self, packet: scapy.all.Packet):
        self.result_.append(packet)

    def scan(self):
        self._set_channel()

        is_dot11 = lambda packet: packet.haslayer(scapy.layers.dot11.Dot11)
        self.result_ = scapy.all.sniff(timeout=self.timeout_, store=True, iface=self.interface_, lfilter=is_dot11)

    def get_result(self) -> List[scapy.packet.Packet]:
        return self.result_


class EAPOLPayloadHeader:
    def __init__(self, payload: bytes):
        status_code = int.from_bytes(payload[1:3], byteorder='big')

        self.is_pairwise = bool((status_code >> 3) & 1)
        self.key_index = (status_code >> 4) & 3
        self.is_install = bool((status_code >> 6) & 1)
        self.is_ack = bool((status_code >> 7) & 1)
        self.is_mic = bool((status_code >> 8) & 1)
        self.is_secure = bool((status_code >> 9) & 1)
        self.is_error = bool((status_code >> 10) & 1)
        self.is_request = bool((status_code >> 11) & 1)

        self.is_encrypted_key_data = bool((status_code >> 12) & 1)
        self.is_smk_message = bool((status_code >> 13) & 1)

    def _is_1_stage(self) -> bool:
        return self.is_ack and not self.is_install and not self.is_mic and \
            not self.is_secure and not self.is_request

    def _is_2_stage(self) -> bool:
        return self.is_mic and not self.is_install and not self.is_ack and \
               not self.is_secure and not self.is_request

    def _is_3_stage(self) -> bool:
        return self.is_ack and self.is_install and self.is_mic and \
               self.is_secure and self.is_encrypted_key_data

    def _is_4_stage(self) -> bool:
        return not self.is_ack and not self.is_install and self.is_mic and \
               self.is_secure and not self.is_request

    def get_stage(self) -> int:
        if self._is_1_stage():
            return 1
        elif self._is_2_stage():
            return 2
        elif self._is_3_stage():
            return 3
        elif self._is_4_stage():
            return 4
        else:
            return -1


class Decoder:
    @staticmethod
    def get_encryption_type(packet: scapy.packet.Packet) -> Optional[str]:
        if packet.haslayer(scapy.layers.dot11.Dot11Elt):
            packet_payload = packet[scapy.layers.dot11.Dot11Elt]
            while isinstance(packet_payload, scapy.layers.dot11.Dot11Elt):
                if packet_payload.ID == 48:
                    return 'wpa2'
                elif packet_payload.ID == 221 and packet_payload.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    return 'wpa'
                packet_payload = packet_payload.payload

            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
            if 'privacy' in cap:  # WEP has been detected
                return 'wep'
            else:  # No crypto
                return 'open'
        return 'unknown'

    @staticmethod
    def find_aps_info(pcap: List[scapy.packet.Packet], channel: Optional[int]=None) -> Dict[str, Dict[str, str]]:
        result = {}
        for packet in pcap:
                if packet.type == 0 and packet.subtype == 8:
                    if packet.addr2 in result:
                        continue
                    essid = None
                    try:
                        essid = packet.info.decode('utf-8')
                    except:
                        essid = str(packet.info)

                    ap_mac = packet.addr2
                    privacy = Decoder.get_encryption_type(packet)
                    result[ap_mac] = {
                        'essid': essid,
                        'privacy': privacy,
                        'channel': channel if channel is not None else -1
                    }

        return result

    @staticmethod
    def find_clients(pcap: List[scapy.packet.Packet],
                     aps_info: Dict[str, Dict[str, str]]):
        k_zero_mac = '00:00:00:00:00:00'
        k_broadcast_mac = 'ff:ff:ff:ff:ff:ff'

        result = {}

        for packet in pcap:

            if packet.type != 2:
                continue

            addr1 = packet.addr1
            addr2 = packet.addr2

            if addr1 == k_zero_mac or addr2 == k_zero_mac:
                continue

            if addr1 == k_broadcast_mac or addr2 == k_broadcast_mac:
                continue

            if addr1 in aps_info and addr2 not in aps_info and addr2 not in result:
                result[addr2] = {}

            if addr2 in aps_info and addr1 not in aps_info and addr1 not in result:
                result[addr1] = {}

        return result

    @staticmethod
    def find_data_transfers(pcap: List[scapy.packet.Packet],
                            aps_info: Dict[str, Dict[str, str]],
                            clients_info: Dict[str, Dict[str, str]]) -> List[Dict[str, str]]:

        k_zero_mac = '00:00:00:00:00:00'
        k_broadcast_mac = 'ff:ff:ff:ff:ff:ff'

        result = collections.defaultdict(int)
        for packet in pcap:

            if packet.type != 2 or packet.subtype < 8 or packet.subtype > 11:
                continue

            addr1 = packet.addr1
            addr2 = packet.addr2

            if addr1 == k_zero_mac or addr2 == k_zero_mac:
                continue

            if addr1 == k_broadcast_mac or addr2 == k_broadcast_mac:
                continue

            if addr1 in aps_info and addr2 in clients_info:
                result[(addr1, addr2)] += len(packet)

            if addr2 in aps_info and addr1 in clients_info:
                result[(addr2, addr1)] += len(packet)

        return [ {
            'ap': ap,
            'client': client,
            'bytes': result[(ap, client)]
        } for ap, client in result ]

    @staticmethod
    def find_client_authorisation(pcap: List[scapy.packet.Packet]) -> List[Dict[str, Union[str, int]]]:
        auth_stages = {}
        for packet in pcap:
            if packet.haslayer(scapy.layers.eap.EAPOL):
                header = EAPOLPayloadHeader(packet[scapy.packet.Raw].load)
                stage = header.get_stage()

                client, ap = None, None
                if stage == 1 or stage == 3:
                    client, ap = packet.addr1, packet.addr2
                elif stage == 2 or stage == 4:
                    client, ap = packet.addr2, packet.addr1

                if not (client, ap) in auth_stages:
                    auth_stages[(client, ap)] = (-1, -1)

                cur_stage, cur_count = auth_stages[(client, ap)]
                if cur_stage == stage:
                    auth_stages[(client, ap)] = (cur_stage, cur_count + 1)
                elif cur_stage < stage:
                    auth_stages[(client, ap)] = (stage, 1)

        return [ {
            'ap': key[1],
            'client': key[0],
            'stage': auth_stages[key][0],
            'tries': auth_stages[key][1]
        } for key in auth_stages ]


    @staticmethod
    def decode_pcap(pcap: List[scapy.packet.Packet], channel: Optional[int] = None) -> ScanResult:
        result = ScanResult()

        # find aps
        result.visible_aps = Decoder.find_aps_info(pcap, channel)
        result.visible_clients = Decoder.find_clients(pcap, result.visible_aps)
        result.client_ap_data_transfer = Decoder.find_data_transfers(pcap, result.visible_aps, result.visible_clients)
        result.client_authorised = Decoder.find_client_authorisation(pcap)
        return result


def CollectInfo(interface: str, channels: Union[List[int], Tuple[int, ...]],
                timeout: Union[int, float]):

    result = []
    for channel in tqdm.tqdm(channels):
        scanner = ScannerEpoch(interface=interface, channel=channel, timeout=timeout)
        scanner.scan()
        pcap = scanner.get_result()
        result.append( Decoder.decode_pcap(pcap, channel) )

    gathered_result = result[0]

    for i in range(1, len(result)):
        new_result = result[i]

        gathered_result.visible_aps.update(new_result.visible_aps)
        gathered_result.visible_clients.update(new_result.visible_clients)
        gathered_result.client_ap_data_transfer.extend(new_result.client_ap_data_transfer)
        gathered_result.client_authorised.extend(new_result.client_authorised)

    return gathered_result

if __name__ == "__main__":
    res = CollectInfo('wlp2s0mon', [1,2,3,4,5,6,7,8,9,10,11,12], timeout=2).get()
    #res = Decoder.decode_pcap(scapy.utils.rdpcap('auth.pcapng')).get()
    res['workspace'] = 'dev_space'
    pprint.pprint(res)
    #requests.post('http://localhost:5000/add_result', json=res)