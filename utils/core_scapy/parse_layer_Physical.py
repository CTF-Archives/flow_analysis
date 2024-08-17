import logging
from rich.progress import Progress
from scapy.data import DLT_EN10MB, DLT_LINUX_SLL
from scapy.layers.l2 import Ether, CookedLinux
from utils.core_scapy.type_scapy import PacketMetadata

filter = {DLT_EN10MB: ("Ether", Ether), DLT_LINUX_SLL: ("SLL", CookedLinux)}


def parse_layer_Physical(data_link_type: int, traffic_data: list[tuple[bytes, PacketMetadata]])-> list[tuple[PacketMetadata, dict[str,dict]]]:
    traffic_data_res: list[tuple[PacketMetadata, dict[str,dict]]] = []
    with Progress() as progress:
        logging.info(f"Start scan in Layer 1 - The Physical Layer")
        packets_progress = progress.add_task("[green]Scanning in Physical Layer...", total=len(traffic_data))

        if data_link_type in filter.keys():
            for pkt_data, pkt_metadata in traffic_data:
                try:
                    packet_type:str = filter.get(data_link_type)[0] # type: ignore
                    packet_data:dict = filter.get(data_link_type)[1](pkt_data) # type: ignore
                    traffic_data_res.append((pkt_metadata, {packet_type: packet_data}))  # type: ignore
                except:
                    logging.error(f"Found {data_link_type} packet parse error!")
                    logging.error(f"Packet's PacketMetadata: {PacketMetadata}")
                    continue
                progress.update(packets_progress, advance=1)
    return traffic_data_res
