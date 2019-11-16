import scapy
import scapy.all

import subprocess
import storage

import progressbar

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
