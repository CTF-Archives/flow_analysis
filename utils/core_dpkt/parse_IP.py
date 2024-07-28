import dpkt
import logging
from rich.progress import Progress


def parse_IP_from_Ether(traffic_data_Ether: list[tuple[float, dpkt.ethernet.Ethernet]]) -> list[tuple[float, dpkt.ip.IP]]:
    # ts, dpkt.ethernet.Ethernet
    traffic_data_Ether_IP: list[tuple[float, dpkt.ip.IP]] = []
    with Progress() as progress:
        packets_progress = progress.add_task("[green]Scaning for IP layer packets...", total=len(traffic_data_Ether))
        for ts, buf in traffic_data_Ether:
            if isinstance(buf.data, dpkt.ip.IP):
                traffic_data_Ether_IP.append((ts, buf.data))
            else:
                logging.debug(f"Found non-IP-layer data!")
                logging.debug(f"Non-IP-layer data's ts: {ts}")
            progress.update(packets_progress, advance=1)
    logging.info(f"Valid IP packets: {len(traffic_data_Ether_IP)}")
    # ts, dpkt.ip.IP
    return traffic_data_Ether_IP
