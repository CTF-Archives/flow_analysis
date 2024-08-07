import dpkt
import logging
from typing import cast
from rich.progress import Progress


def parse_layer_DataLink(traffic_data: list[tuple[float, dict[str, dpkt.Packet]]]) -> list[tuple[float, dict[str, dpkt.Packet]]]:
    # traffic_data -> [(ts, dict["Ethernet" : dpkt.ethernet.Ethernet]), ...]
    traffic_data_layer_physical: list[tuple[float, dict]] = []
    with Progress() as progress:
        logging.info(f"Start scan in Layer 2 - The Data Link Layer")
        packets_progress = progress.add_task("[green]Scanning in Data Link Layer...", total=len(traffic_data))
        for index, (ts, packet_dict) in enumerate(traffic_data):
            layer_DataLink_type = cast(int, packet_dict[list(packet_dict.keys())[0]].type)  # type: ignore
            match layer_DataLink_type:
                case dpkt.ethernet.ETH_TYPE_IP:
                    packet_dict["IP"] = cast(dpkt.Packet, packet_dict[list(packet_dict.keys())[0]].data)
                    traffic_data[index] = (ts, packet_dict)
                case dpkt.ethernet.ETH_TYPE_ARP:
                    packet_dict["ARP"] = cast(dpkt.Packet, packet_dict[list(packet_dict.keys())[0]].data)
                    traffic_data[index] = (ts, packet_dict)
                case _:
                    logging.error("Unsupported data link type!")

            # try:
            #     traffic_data_layer_physical.append((ts, {"Ethernet": dpkt.ethernet.Ethernet(buf)}))
            # except:
            #     logging.debug(f"Found non-Ether-layer data!")
            #     logging.debug(f"Non-Ether-layer data's ts: {ts}")
            progress.update(packets_progress, advance=1)
    logging.info(f"Valid Data Link Layer - Ethernet packets: {len(traffic_data_layer_physical)}")
    # ts, dpkt.ethernet.Ethernet
    return traffic_data_layer_physical
