import argparse
import collections
import getpass
import json
import multiprocessing
import pickle
import pprint
import re
import subprocess
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

import requests
import scapy
import scapy.all
import scapy.layers.dot11
import scapy.layers.eap
import scapy.packet
import scapy.sendrecv
import scapy.utils
import tqdm


class ScanResult:
    def __init__(self):
        self.visible_aps = dict()
        self.visible_clients = dict()
        self.client_ap_data_transfer = list()
        self.client_authorised = list()

    def get(self) -> Dict[str, Any]:
        result = {
            "visible_aps": self.visible_aps,
            "visible_clients": self.visible_clients,
            "client_ap_data_transfer": self.client_ap_data_transfer,
            "client_authorised": self.client_authorised,
        }
        return result

    def __str__(self) -> str:
        return json.dumps(self.get(), sort_keys=True)


class ScannerEpoch:
    def __init__(self, interface: str, channel: int = None, timeout: int = 2):
        self.interface_ = interface
        self.channel_ = channel
        self.timeout_ = timeout
        self.result_ = []

    def _set_channel(self) -> None:
        if channel is not None:
            subprocess.run(["iwconfig", self.interface_, "channel", str(self.channel_)])

    def _push_back_cp(self, packet: scapy.packet.Packet):
        self.result_.append(packet)

    def scan(self):
        self._set_channel()

        is_dot11 = lambda packet: packet.haslayer(scapy.layers.dot11.Dot11)
        self.result_ = scapy.all.sniff(
            timeout=self.timeout_, store=True, iface=self.interface_, lfilter=is_dot11
        )
        return self

    def get_result(self) -> List[scapy.packet.Packet]:
        return [packet for packet in self.result_]


class EAPOLPayloadHeader:
    def __init__(self, payload: bytes):
        status_code = int.from_bytes(payload[1:3], byteorder="big")

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
        return (
            self.is_ack
            and not self.is_install
            and not self.is_mic
            and not self.is_secure
            and not self.is_request
        )

    def _is_2_stage(self) -> bool:
        return (
            self.is_mic
            and not self.is_install
            and not self.is_ack
            and not self.is_secure
            and not self.is_request
        )

    def _is_3_stage(self) -> bool:
        return (
            self.is_ack and self.is_install and self.is_mic and self.is_secure and self.is_encrypted_key_data
        )

    def _is_4_stage(self) -> bool:
        return (
            not self.is_ack and not self.is_install and self.is_mic and self.is_secure and not self.is_request
        )

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
                    return "wpa2"
                elif packet_payload.ID == 221 and packet_payload.info.startswith(b"\x00P\xf2\x01\x01\x00"):
                    return "wpa"
                packet_payload = packet_payload.payload

            cap = packet.sprintf(
                "{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}"
            ).split("+")
            if "privacy" in cap:  # WEP has been detected
                return "wep"
            else:  # No crypto
                return "open"
        return "unknown"

    @staticmethod
    def find_aps_info(
        pcap: List[scapy.packet.Packet], channel: Optional[int] = None
    ) -> Dict[str, Dict[str, str]]:
        result = {}
        for packet in pcap:
            if packet.type == 0 and packet.subtype == 8:
                if packet.addr2 in result:
                    continue
                essid = None
                try:
                    essid = packet.info.decode("utf-8")
                except:
                    essid = str(packet.info)

                ap_mac = packet.addr2
                privacy = Decoder.get_encryption_type(packet)

                local_channel = channel
                try:
                    local_channel = packet.getlayer(scapy.layers.dot11.RadioTap).Channel
                except Exception:
                    pass

                result[ap_mac] = {
                    "essid": essid,
                    "privacy": privacy,
                    "channel": local_channel if local_channel is not None else local_channel,
                }

        return result

    @staticmethod
    def find_clients(pcap: List[scapy.packet.Packet], aps_info: Dict[str, Dict[str, str]]):
        k_zero_mac = "00:00:00:00:00:00"
        k_broadcast_mac = "ff:ff:ff:ff:ff:ff"

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
    def find_data_transfers(
        pcap: List[scapy.packet.Packet],
        aps_info: Dict[str, Dict[str, str]],
        clients_info: Dict[str, Dict[str, str]],
    ) -> List[Dict[str, str]]:

        k_zero_mac = "00:00:00:00:00:00"
        k_broadcast_mac = "ff:ff:ff:ff:ff:ff"

        result = collections.defaultdict(int)
        for packet in pcap:

            if not packet.haslayer(scapy.layers.dot11.Dot11QoS) or len(packet) < 250:
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

        return [{"ap": ap, "client": client, "bytes": result[(ap, client)]} for ap, client in result]

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

        return [
            {"ap": key[1], "client": key[0], "stage": auth_stages[key][0], "tries": auth_stages[key][1]}
            for key in auth_stages
        ]

    @staticmethod
    def find_active_clients(data_transfers: List[Dict[str, str]], auth: List[Dict[str, Union[str, int]]]):
        result = {}
        for transfer in data_transfers:
            result[transfer["client"]] = {}

        for auth in auth:
            result[auth["client"]] = {}

        return result

    @staticmethod
    def decode_pcap(pcap: List[scapy.packet.Packet], channel: Optional[int] = None) -> ScanResult:
        result = ScanResult()

        # find aps
        result.visible_aps = Decoder.find_aps_info(pcap, channel)
        result.visible_clients = Decoder.find_clients(pcap, result.visible_aps)
        result.client_ap_data_transfer = Decoder.find_data_transfers(
            pcap, result.visible_aps, result.visible_clients
        )
        result.client_authorised = Decoder.find_client_authorisation(pcap)

        # filter by activity
        result.visible_clients = Decoder.find_active_clients(
            result.client_ap_data_transfer, result.client_authorised
        )
        return result


def CollectInfo(interface: str, channels: Union[List[int], Tuple[int, ...]], timeout: Union[int, float]):
    result = []
    for channel in tqdm.tqdm(channels):
        scanner = ScannerEpoch(interface=interface, channel=channel, timeout=timeout)
        scanner.scan()
        pcap = scanner.get_result()
        result.append(Decoder.decode_pcap(pcap, channel))

    gathered_result = result[0]

    for i in range(1, len(result)):
        new_result = result[i]

        gathered_result.visible_aps.update(new_result.visible_aps)
        gathered_result.visible_clients.update(new_result.visible_clients)
        gathered_result.client_ap_data_transfer.extend(new_result.client_ap_data_transfer)
        gathered_result.client_authorised.extend(new_result.client_authorised)

    return gathered_result


def auth(session: requests.Session, uri: str, username: str, password: str):
    try:
        index = session.get(uri + "/index")
        reg = re.compile('csrf_token.*?value="([^"]*?)"')
        csrf_token = reg.search(index.text).group(1)
        auth_response = session.post(
            uri + "/login",
            data={"username": username, "password": password, "csrf_token": csrf_token, "submit": "Login"},
            allow_redirects=False,
        )
        if auth_response.status_code == 303:
            return True
        else:
            return False
    except Exception:
        return False


def worker(queue: multiprocessing.Queue, session_to_send_result: requests.Session, url: str):
    decoder = Decoder
    while True:
        try:
            data_to_process = queue.get()
            if data_to_process is None:
                return

            pcap, workspace = data_to_process
            if isinstance(pcap, str):
                pcap = scapy.utils.rdpcap(pcap)
            else:
                pcap = pickle.loads(pcap)

            res = decoder.decode_pcap(pcap).get()
            res["workspace"] = workspace
            try:
                resp = session_to_send_result.post(url + "/add_result", json=res)
                if resp.text == "Permission denied":
                    print(
                        'You do not have permissions to add results, you must be member of "collectors" group in server'
                    )
            except:
                print("Data were processed but weren't submitted to server")
        except Exception as e:
            print("Error:", e)


def logger(queue: multiprocessing.Queue):
    while True:
        print(">> {} active tasks".format(queue.qsize()) + " " * 10, end="\r")
        time.sleep(0.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        required=False,
        help="interface to listen, mode must be set to monitor manually",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        nargs="*",
        help="path to input pcap or space separated list of pcaps to parse and visualize",
    )
    parser.add_argument(
        "-H",
        "--host",
        type=str,
        default="localhost",
        required=False,
        help="host to send results, localhost is default, port may be specified",
    )
    parser.add_argument(
        "-c",
        "--channel",
        type=int,
        nargs="*",
        default=[],
        required=False,
        help="channel or space separated list of channels to listen, if not specified, "
        "current channel of interface will be used",
    )
    parser.add_argument(
        "-v", "--verbose", required=False, action="store_true", help="show additional info in stdout"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=4, required=False, help="time to parse one channel"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        required=False,
        help="iterations over scanning channels, -1 means infinity",
    )
    parser.add_argument(
        "-u", "--username", type=str, required=True, help="username to use in visualisation server"
    )
    parser.add_argument(
        "-W",
        "--workers",
        type=int,
        default=1,
        required=False,
        help="num workers to process traffic, 1 is default",
    )
    parser.add_argument(
        "-w", "--workspace", type=str, required=True, help="name of workspace to place results"
    )

    args = parser.parse_args()
    if args.verbose:
        print(args)

    if args.file is None and args.interface is None:
        print("Input pcap file or interface must be specified")

    args.host = args.host if args.host.startswith("http") else "http://" + args.host

    session = requests.Session()
    if not auth(
        session,
        args.host,
        args.username,
        getpass.getpass(prompt="Password to authorize in {}: ".format(args.host)),
    ):
        print("Host, username or password isn't correct")
        exit(-1)

    queue = multiprocessing.Queue()
    workers = [
        multiprocessing.Process(target=worker, args=(queue, session, args.host)) for _ in range(args.workers)
    ]
    for worker in workers:
        worker.start()

    log = multiprocessing.Process(target=logger, args=(queue,))
    log.start()

    # process input files
    if args.file is not None:
        print("Opening pcap files: ")
        for file in args.file:
            print("> {}".format(file))
            queue.put((file, args.workspace))
        print("-" * 50)
    else:
        print("Pcap files wasn't found")

    scans = 0

    # scan
    if args.interface is not None:
        print("Scaning interfaces {} for {} iterations".format(args.interface, args.iterations))
        if not args.channel:
            args.channel = [None]

        if args.iterations == -1:
            args.iterations = int(1e10)
        for _ in range(args.iterations):
            for channel in args.channel:
                print("Channel: {}, Interface: {}".format(channel, args.interface))
                result = ScannerEpoch(interface=args.interface, channel=channel, timeout=args.timeout)
                pcap = result.scan().get_result()
                queue.put((pickle.dumps(pcap), args.workspace))

    for _ in range(args.workers):
        queue.put(None)

    for worker in workers:
        worker.join()

    log.terminate()
    log.join()
