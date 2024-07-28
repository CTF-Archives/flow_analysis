import logging
from collections import defaultdict
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from rich.progress import Progress


def match_http_sessions(http_requests: defaultdict, http_responses: defaultdict) -> list:
    matched_sessions = []
    for session_id, reqs in http_requests.items():
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


def is_http_request(payload: str | bytes) -> tuple[bool, str]:
    if type(payload) == str:
        payload_operatpr = payload.split(" ", maxsplit=1)[0]
        match payload_operatpr:
            case "GET":
                return True, "GET"
            case "POST":
                return True, "POST"
            case "PUT":
                return True, "PUT"
            case "DELETE":
                return True, "DELETE"
            case "PATCH":
                return True, "PATCH"
            case "HEAD":
                return True, "HEAD"
            case "OPTIONS":
                return True, "OPTIONS"
            case "PROPFIND":
                return True, "PROPFIND"
            case _:
                return False, ""
    elif type(payload) == bytes:
        try:
            payload_operatpr = payload.split(b" ", maxsplit=1)[0].decode()
        except:
            return False, ""
        match payload.split(b" ", maxsplit=1)[0].decode():
            case "GET":
                return True, "GET"
            case "POST":
                return True, "POST"
            case "PUT":
                return True, "PUT"
            case "DELETE":
                return True, "DELETE"
            case "PATCH":
                return True, "PATCH"
            case "HEAD":
                return True, "HEAD"
            case "OPTIONS":
                return True, "OPTIONS"
            case "PROPFIND":
                return True, "PROPFIND"
            case _:
                return False, ""
    else:
        return False, ""


def is_http_response(payload: str) -> bool:
    try:
        return payload.startswith("HTTP/")
    except:
        return False


def parse_http_sessions(pcap_file: str) -> tuple[defaultdict, defaultdict]:

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
                payload = str(raw_layer.load.decode(errors="ignore"))
                if payload.startswith("HTTP/1.1 200"):
                    pass
                session_id = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
                # logging.debug(session_id)

                if is_http_request(payload)[0]:
                    http_requests[session_id].append(pkt)
                elif is_http_response(payload):
                    reverse_session_id = (ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport)
                    http_responses[reverse_session_id].append(pkt)
            progress.update(packets_progress, advance=1)
    logging.info(f"HTTP request packets quantity: {len(http_requests)}")
    logging.info(f"HTTP response packets quantity: {len(http_responses)}")
    return http_requests, http_responses
