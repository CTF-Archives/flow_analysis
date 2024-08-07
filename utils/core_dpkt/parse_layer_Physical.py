import dpkt
import logging
from rich.progress import Progress


def parse_layer_Physical(data_link_type: int, traffic_data: list[tuple[float, bytes]]) -> list[tuple[float, dict[str, dpkt.Packet]]]:
    # traffic_data -> [(ts, bytes),...]
    traffic_data_res: list[tuple[float, dict[str, dpkt.Packet]]] = []
    with Progress() as progress:
        logging.info(f"Start scan in Layer 1 - The Physical Layer")
        packets_progress = progress.add_task("[green]Scanning in Physical Layer...", total=len(traffic_data))

        match data_link_type:
            case dpkt.pcap.DLT_EN10MB:
                for ts, buf in traffic_data:
                    try:
                        traffic_data_res.append((ts, {"Ethernet": dpkt.ethernet.Ethernet(buf)}))
                    except:
                        logging.debug(f"Found DLT_EN10MB - Ethernet data!")
                        logging.debug(f"Raw data's ts: {ts}")
                    progress.update(packets_progress, advance=1)
            case dpkt.pcap.DLT_IEEE802_11:
                for ts, buf in traffic_data:
                    try:
                        traffic_data_res.append((ts, {"IEEE80211": dpkt.ieee80211.IEEE80211(buf)}))
                    except:
                        logging.debug(f"Found DLT_IEEE802_11 - IEEE80211!")
                        logging.debug(f"Raw data's ts: {ts}")
                    progress.update(packets_progress, advance=1)
            case dpkt.pcap.DLT_LINUX_SLL:
                for ts, buf in traffic_data:
                    try:
                        traffic_data_res.append((ts, {"SLL": dpkt.sll.SLL(buf)}))
                    except:
                        logging.debug(f"Found DLT_LINUX_SLL - SLL!")
                        logging.debug(f"Raw data's ts: {ts}")
                    progress.update(packets_progress, advance=1)
            case dpkt.pcap.DLT_PPP:
                for ts, buf in traffic_data:
                    try:
                        traffic_data_res.append((ts, {"PPP": dpkt.ppp.PPP(buf)}))
                    except:
                        logging.debug(f"Found DLT_PPP - PPP!")
                        logging.debug(f"Raw data's ts: {ts}")
                    progress.update(packets_progress, advance=1)
            case dpkt.pcap.DLT_USBPCAP:
                for ts, buf in traffic_data:
                    try:
                        traffic_data_res.append((ts, {"PPP": dpkt.ppp.PPP(buf)}))
                    except:
                        logging.debug(f"Found DLT_PPP - PPP!")
                        logging.debug(f"Raw data's ts: {ts}")
                    progress.update(packets_progress, advance=1)
            case _:
                logging.critical(f"Unsupported Physical Layer!")
                exit()

    logging.info(f"Valid Physical Layer - Ethernet packets: {len(traffic_data_res)}")
    # ts, dpkt.ethernet.Ethernet
    return traffic_data_res
