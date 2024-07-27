import os
import pickle
import logging
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from rich.logging import RichHandler
from collections import defaultdict
from rich.progress import Progress
import hashlib
from time import sleep

FORMAT = "%(message)s"
logging.basicConfig(level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()])


def calculate_file_hash(file_path: str, hash_type="sha1") -> str:
    hash_func = hashlib.new(hash_type)

    # 以二进制模式读取文件并计算哈希
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def is_http_request(payload: str) -> bool:
    try:
        return payload.startswith(b"GET") or payload.startswith(b"POST") or payload.startswith(b"PUT") or payload.startswith(b"DELETE") or payload.startswith(b"HEAD") or payload.startswith(b"OPTIONS")
    except:
        return False


def is_http_response(payload: str) -> bool:
    try:
        return payload.startswith(b"HTTP/")
    except:
        return False


def extract_http_sessions(pcap_file: str) -> tuple[list, list]:

    logging.info(f"Extracting HTTP Sessions...")

    http_requests = defaultdict(list)
    http_responses = defaultdict(list)

    logging.info("Calculating packets quantity...")

    _count = 0
    for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
        _count += 1

    logging.info(f"Packets quantity: {_count}")

    with Progress() as progress:
        packets_progress = progress.add_task("[green]Scaning for HTTP packets...", total=_count)
        for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
            pkt = Ether(pkt_data)
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                ip_layer = pkt[IP]
                tcp_layer = pkt[TCP]
                raw_layer = pkt[Raw]
                payload = raw_layer.load
                session_id = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
                # logging.debug(session_id)

                if is_http_request(payload):
                    http_requests[session_id].append(pkt)
                elif is_http_response(payload):
                    reverse_session_id = (ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport)
                    http_responses[reverse_session_id].append(pkt)
            progress.update(packets_progress, advance=1)
    logging.info(f"HTTP request packets quantity: {len(http_requests)}")
    logging.info(f"HTTP response packets quantity: {len(http_responses)}")
    return http_requests, http_responses


def match_http_sessions(http_requests: list, http_responses: list) -> list:
    matched_sessions = []

    for session_id, reqs in http_requests:
        if session_id in http_responses:
            try:
                responses = http_responses[session_id]
            except:
                logging.error(f"Unmatched HTTP request packets: {session_id}")
            for req in reqs:
                for res in responses:
                    matched_sessions.append((req, res))
    logging.info(f"Valid HTTP communication quantity: {len(matched_sessions)}")
    return matched_sessions


if __name__ == "__main__":
    pcap_file = "./output.pcap"
    logging.info(f"Loading traffic package file: {pcap_file}")
    if os.path.isfile(pcap_file):
        pcap_file_nash = calculate_file_hash(pcap_file, "sha1")
        logging.info(f"Traffic package file SHA-1 hash: {pcap_file_nash}")
    else:
        logging.error(f"Traffic package file does not exist!")
        exit()
    logging.info(f"Loading traffic package file cache: {pcap_file_nash}.flow.http")
    if os.path.isfile(pcap_file_nash + ".flow.http"):
        with open(pcap_file_nash + ".flow.hash", "rb") as f:
            http_requests, http_responses = pickle.load(f)
    else:
        logging.error(f"Cache file does not exist!")
        http_requests, http_responses = extract_http_sessions(pcap_file)
        with open(pcap_file_nash + ".flow.http", "wb") as f:
            pickle.dump((http_requests, http_responses), f)

    matched_sessions = match_http_sessions(http_requests, http_responses)
    logging.info(f"Total matched HTTP sessions: {len(matched_sessions)}")

    for req, res in matched_sessions:
        logging.info("Request:")
        logging.info(req[Raw].load.decode(errors="ignore"))
        logging.info("Response:")
        logging.info(res[Raw].load.decode(errors="ignore"))
        logging.info("------")
