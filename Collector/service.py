import pprint
import json
import queue
import subprocess

from typing import List, Set, Tuple, Optional, Dict, Any

import scapy
import scapy.packet
import scapy.layers.dot11
import scapy.utils
import scapy.all

import subprocess

class ScannerEpochResult:
    def __init__(self):
        self.visible_aps = dict()
        self.visible_clients = dict()
        self.client_ap_data_transfer = set()
        self.client_authorised = set()
        self.packet_lengths = list()

    def get(self) -> Dict[str, Any]:
        result = {
            'visible_aps': self.visible_aps,
            'visible_clients': self.visible_clients,
            'client_ap_data_transfer': self.client_ap_data_transfer,
            'client_authorised': self.client_authorised,
            'packet_lengths': [{'client': client_mac, 'ap': ap_mac, 'packet_length': packet_length, 'packet_hash': packet_hash}
                               for client_mac, ap_mac, packet_length, packet_hash in self.packet_lengths]
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


class Decoder:
    @staticmethod
    def get_encryption_type(packet: scapy.packet.Packet) -> Optional[str]:
        if packet.haslayer(scapy.layers.dot11.Dot11Elt):
            packet_payload = packet[scapy.all.Dot11Elt]
            while isinstance(packet_payload, scapy.all.Dot11Elt):
                if packet_payload.ID == 48:
                    return 'wpa2'
                elif packet_payload.ID == 221 and packet_payload.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    return 'wpa'
                packet_payload = packet_payload.payload

            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
            print(cap)
            if 'privacy' in cap:  # WEP has been detected
                return 'wep'
            else:  # No crypto
                return 'open'
        return None

    @staticmethod
    def find_aps_info(pcap: List[scapy.packet.Packet]) -> Dict[str, Dict[str, str]]:
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
                        'privacy': privacy
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
                            clients_info: Dict[str, Dict[str, str]]):

        k_zero_mac = '00:00:00:00:00:00'
        k_broadcast_mac = 'ff:ff:ff:ff:ff:ff'

        result = set()

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
                result.add((addr1, addr2))

            if addr2 in aps_info and addr1 in clients_info:
                result.add((addr2, addr1))

        return [ {'ap': ap, 'client': client} for ap, client in result ]

    @staticmethod
    def decode_pcap(pcap: List[scapy.packet.Packet]) -> ScannerEpochResult:
        result = ScannerEpochResult()

        # find aps
        result.visible_aps = Decoder.find_aps_info(pcap)
        result.visible_clients = Decoder.find_clients(pcap, result.visible_aps)
        result.client_ap_data_transfer = Decoder.find_data_transfers(pcap, result.visible_aps, result.visible_clients)

        return result



class Scanner:

    def __init__(self, interface: str, timeout: int = 4, channel_list: list = None):
        self.interface = interface
        self.timeout = timeout
        self.channel_list = channel_list

        self.ap_storage = storage.ApStorage()
        self.clients_storage = storage.ClientStorage()

        self.tmp_ap_storage = set() # set of pairs
        self.tmp_clients_storage = set() # set of pairs
        self.tmp_ap_check_list = set() # set of bytes

        self.k_zero_mac = b'00:00:00:00:00:00'
        self.k_broadcast_mac = b'ff:ff:ff:ff:ff:ff'

    @staticmethod
    def check_ap_for_open(packet: scapy.all.Packet) -> bool:
        if packet.haslayer(scapy.all.Dot11Elt):
            packet_payload = packet[scapy.all.Dot11Elt]
            while isinstance(packet_payload, scapy.all.Dot11Elt):
                if packet_payload.ID == 48:  # WPA2 has been found
                    return False
                elif packet_payload.ID == 221 and packet_payload.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    # WPA has been found
                    return False
                packet_payload = packet_payload.payload

            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
            if 'privacy' in cap:  # WEP has been detected
                return False
            else:  # No crypto
                return True

        return False

    def sniff_handler(self, packet: scapy.all.Packet):
        if packet.haslayer(scapy.all.Dot11):
            i


            if packet.type == 0 and packet.subtype == 8 and packet.addr2 not in self.tmp_ap_check_list and \
                                Scanner.check_ap_for_open(packet):
                # beacon frame
                self.tmp_ap_storage.add((packet.addr2.encode(), packet.info))
                self.tmp_ap_check_list.add(packet.addr2.encode())

            if packet.type == 2:
                # data transfer
                addr1 = packet.addr1.encode()
                addr2 = packet.addr2.encode()

                if addr1 == self.k_broadcast_mac or addr2 == self.k_broadcast_mac:
                    pass
                elif addr1 == self.k_zero_mac or addr2 == self.k_zero_mac:
                    pass
                else:
                    self.tmp_clients_storage.add((addr1, addr2))

    def run(self, interface: str=None, channel_list: list=None, timeout: float=None):

        if interface is None:
            interface = self.interface

        if timeout is None:
            timeout = self.timeout

        if channel_list is None:
            channel_list = self.channel_list

        if channel_list is None or not isinstance(channel_list, list) or len(channel_list) == 0:
            with progressbar.ProgressBar(timeout, 'Default channel: ') as p:
                scapy.all.sniff(iface=interface, timeout=timeout, prn=self.sniff_handler)

        else:
            # jump over channels
            time_for_channel = timeout / len(channel_list)

            for channel in channel_list:
                subprocess.run(['iwconfig', interface, 'channel', str(channel)])
                with progressbar.ProgressBar(time_for_channel, 'Channel {:2d}/{}: '.format(
                            channel, progressbar.Formatter.format_list(channel_list))) as p:
                    scapy.all.sniff(iface=interface, timeout=time_for_channel, prn=self.sniff_handler)

        tmp_clients = set()

        # reorder packets
        for addr1, addr2 in self.tmp_clients_storage:
            if addr1 in self.tmp_ap_check_list and not addr2 in self.tmp_ap_check_list:
                tmp_clients.add((addr1, addr2))

            if not addr1 in self.tmp_ap_check_list and addr2 in self.tmp_ap_check_list:
                tmp_clients.add((addr2, addr1))

        self.ap_storage.insert_pairs(list(self.tmp_ap_storage))
        self.clients_storage.insert_pairs(list(tmp_clients))

    def get_ap_storage(self):
        return self.ap_storage

    def get_clients_storage(self):
        return self.clients_storage

if __name__ == "__main__":
    pcap = scapy.utils.rdpcap('sample.pcapng')
    res = Decoder.decode_pcap(pcap)
    pprint.pprint(res.get())
