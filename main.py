import logging
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from rich.logging import RichHandler
from collections import defaultdict
from rich.progress import Progress
from rich.progress import Progress, BarColumn, TextColumn
from rich.live import Live
from rich.console import Console
from time import sleep

FORMAT = "%(message)s"
logging.basicConfig(level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()])


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

    http_requests = defaultdict(list)
    http_responses = defaultdict(list)

    logging.info("Calculating packets quantity...")

    _count = 0
    for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
        _count += 1

    logging.info(f"Packets quantity: {_count}")

    packets_progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
    )

    # Create a task
    task_id = packets_progress.add_task("[green]Scaning for HTTP packets...", total=_count)

    with Live(packets_progress, console=Console(), refresh_per_second=10):
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
            packets_progress.update(task_id, advance=1)
    return http_requests, http_responses


def match_http_sessions(http_requests: list, http_responses: list) -> list:
    matched_sessions = []

    for session_id, reqs in http_requests.items():
        if session_id in http_responses:
            responses = http_responses[session_id]
            for req in reqs:
                for res in responses:
                    matched_sessions.append((req, res))

    return matched_sessions


if __name__ == "__main__":
    pcap_file = "./output.pcap"
    http_requests, http_responses = extract_http_sessions(pcap_file)
    matched_sessions = match_http_sessions(http_requests, http_responses)
    logging.info(f"Total matched HTTP sessions: {len(matched_sessions)}")

    for req, res in matched_sessions:
        logging.info("Request:")
        logging.info(req[Raw].load.decode(errors="ignore"))
        logging.info("Response:")
        logging.info(res[Raw].load.decode(errors="ignore"))
        logging.info("------")
