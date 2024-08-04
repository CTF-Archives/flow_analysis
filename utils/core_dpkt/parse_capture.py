import dpkt
import logging
from rich.progress import Progress


def parse_pcap_file(pcap_file: str) -> list[tuple[float, bytes]]:
    traffic_data: list[tuple[float, bytes]] = []
    with Progress() as progress, open(pcap_file, "rb") as _f:
        logging.info("Calculating packets quantity...")
        _count = 0
        for ts, buf in dpkt.pcap.Reader(_f):
            _count += 1
        logging.info(f"Packets quantity: {_count}")
        _f.seek(0, 0)
        packets_progress = progress.add_task("[green]Scaning for raw packets...", total=_count)
        for ts, buf in dpkt.pcap.Reader(_f):
            traffic_data.append((ts, buf))
            progress.update(packets_progress, advance=1)
    logging.info(f"Valid raw packets: {len(traffic_data)}")
    # ts, bytes
    return traffic_data


def parse_pcapng_file(pcapng_file: str) -> list[tuple[float, bytes]]:
    traffic_data: list[tuple[float, bytes]] = []
    with Progress() as progress, open(pcapng_file, "rb") as _f:
        logging.info("Calculating packets quantity...")
        _count = 0
        for ts, buf in dpkt.pcapng.Reader(_f):
            _count += 1
        logging.info(f"Packets quantity: {_count}")
        _f.seek(0, 0)
        packets_progress = progress.add_task("[green]Scaning for raw packets...", total=_count)
        for ts, buf in dpkt.pcapng.Reader(_f):
            traffic_data.append((ts, buf))
            progress.update(packets_progress, advance=1)
    logging.info(f"Valid raw packets: {len(traffic_data)}")
    # ts, bytes
    return traffic_data


def parse_capture_file(file_path: str) -> list[tuple[float, bytes]] | None:
    if file_path.endswith("pcap"):
        return parse_pcap_file(file_path)
    elif file_path.endswith("pcapng"):
        return parse_pcapng_file(file_path)
    else:
        return None
