import dpkt
import logging
from rich.progress import Progress


def parse_Ether_from_traffic(traffic_data: list[tuple]) -> list[tuple[float, dpkt.ethernet.Ethernet]]:
    # ts, bytes
    traffic_data_Ether: list[tuple[float, dpkt.ethernet.Ethernet]] = []
    with Progress() as progress:
        packets_progress = progress.add_task("[green]Scaning for Ether layer packets...", total=len(traffic_data))
        for ts, buf in traffic_data:
            try:
                traffic_data_Ether.append((ts, dpkt.ethernet.Ethernet(buf)))
            except:
                logging.debug(f"Found non-Ether-layer data!")
                logging.debug(f"Non-Ether-layer data's ts: {ts}")
            progress.update(packets_progress, advance=1)
    logging.info(f"Valid Ether packets: {len(traffic_data_Ether)}")
    # ts, dpkt.ethernet.Ethernet
    return traffic_data_Ether
