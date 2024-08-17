import logging
from typing import cast
from rich.progress import Progress
from scapy.data import DLT_EN10MB
from scapy.utils import RawPcapReader, RawPcapNgReader
from utils.core_scapy.type_scapy import PacketMetadata


def parse_pcap_file(pcap_file: str) -> tuple[int, list[tuple[bytes, PacketMetadata]]]:
    traffic_data: list[tuple[bytes, PacketMetadata]] = []
    RawPcapReader(pcap_file).linktype
    with Progress() as progress:
        logging.info("Calculating raw packets quantity...")
        _count = 0
        for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
            _count += 1
        logging.info(f"Packets quantity: {_count}")
        packets_progress = progress.add_task("[green]Scanning for raw packets...", total=_count)
        for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
            traffic_data.append((pkt_data, pkt_metadata))
            progress.update(packets_progress, advance=1)
        data_link_type = cast(int, RawPcapReader(pcap_file).linktype)
    logging.info(f"Physical Layer Protocol ID: {data_link_type}")
    logging.info(f"Valid raw packets: {len(traffic_data)}")
    # data_link_type, list[(pkt_data, pkt_metadata), ...]
    return data_link_type, traffic_data


def parse_pcapng_file(pcap_file: str) -> tuple[int, list[tuple[bytes, PacketMetadata]]]:
    traffic_data: list[tuple[bytes, PacketMetadata]] = []
    with Progress() as progress:
        logging.info("Calculating raw packets quantity...")
        _count = 0
        for pkt_data, pkt_metadata in RawPcapNgReader(pcap_file):
            _count += 1
        logging.info(f"Packets quantity: {_count}")
        packets_progress = progress.add_task("[green]Scanning for raw packets...", total=_count)
        for pkt_data, pkt_metadata in RawPcapNgReader(pcap_file):
            traffic_data.append((pkt_data, pkt_metadata))
            progress.update(packets_progress, advance=1)
        data_link_type = cast(int, RawPcapNgReader(pcap_file).linktype)
    logging.info(f"Physical Layer Protocol ID: {data_link_type}")
    logging.info(f"Valid raw packets: {len(traffic_data)}")
    # data_link_type, list[(pkt_data, pkt_metadata), ...]
    return data_link_type, traffic_data


def parse_capture_file(file_path: str) -> tuple[int, list[tuple[bytes, PacketMetadata]]]:
    if file_path.endswith("pcap"):
        return parse_pcap_file(file_path)
    elif file_path.endswith("pcapng"):
        return parse_pcapng_file(file_path)
    else:
        logging.error(f"Unsupported file format: {file_path}")
        exit()
