import dpkt
import logging
from typing import cast
from rich.progress import Progress


def parse_pcap_file(pcap_file: str) -> tuple[int, list[tuple[float, bytes]]]:
    traffic_data: list[tuple[float, bytes]] = []
    with Progress() as progress, open(pcap_file, "rb") as _f:
        logging.info("Calculating raw packets quantity...")
        _count = 0
        for ts, buf in dpkt.pcap.Reader(_f):
            _count += 1
        logging.info(f"Packets quantity: {_count}")
        _f.seek(0, 0)
        packets_progress = progress.add_task("[green]Scanning for raw packets...", total=_count)
        for ts, buf in dpkt.pcap.Reader(_f):
            traffic_data.append((ts, buf))
            progress.update(packets_progress, advance=1)
        _f.seek(0, 0)
        data_link_type = cast(int, dpkt.pcapng.Reader(_f).datalink())
    logging.info(f"Physical Layer Protocol ID: {data_link_type}")
    logging.info(f"Valid raw packets: {len(traffic_data)}")
    # ts, bytes
    return data_link_type, traffic_data


def parse_pcapng_file(pcapng_file: str) -> tuple[int, list[tuple[float, bytes]]]:
    traffic_data: list[tuple[float, bytes]] = []
    with Progress() as progress, open(pcapng_file, "rb") as _f:
        logging.info("Calculating raw packets quantity...")
        _count = 0
        for ts, buf in dpkt.pcapng.Reader(_f):
            _count += 1
        logging.info(f"Packets quantity: {_count}")
        _f.seek(0, 0)
        packets_progress = progress.add_task("[green]Scanning for raw packets...", total=_count)
        for ts, buf in dpkt.pcapng.Reader(_f):
            traffic_data.append((ts, buf))
            progress.update(packets_progress, advance=1)
        _f.seek(0, 0)
        data_link_type = cast(int, dpkt.pcapng.Reader(_f).datalink())
    logging.info(f"Physical Layer Protocol ID: {data_link_type}")
    logging.info(f"Valid raw packets: {len(traffic_data)}")
    # ts, bytes
    return data_link_type, traffic_data


def parse_capture_file(file_path: str) -> tuple[int, list[tuple[float, bytes]]]:
    if file_path.endswith("pcap"):
        return parse_pcap_file(file_path)
    elif file_path.endswith("pcapng"):
        return parse_pcapng_file(file_path)
    else:
        logging.error(f"Unsupported file format: {file_path}")
        exit()
