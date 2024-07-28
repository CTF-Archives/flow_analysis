import dpkt
import logging
from typing import cast
from collections import defaultdict
from rich.progress import Progress


def tcp_flag_detect(tcp_flags: int) -> str:
    ret = ""
    if tcp_flags & dpkt.tcp.TH_FIN:
        ret = ret + "F"
    if tcp_flags & dpkt.tcp.TH_SYN:
        ret = ret + "S"
    if tcp_flags & dpkt.tcp.TH_RST:
        ret = ret + "R"
    if tcp_flags & dpkt.tcp.TH_PUSH:
        ret = ret + "P"
    if tcp_flags & dpkt.tcp.TH_ACK:
        ret = ret + "A"
    if tcp_flags & dpkt.tcp.TH_URG:
        ret = ret + "U"
    if tcp_flags & dpkt.tcp.TH_ECE:
        ret = ret + "E"
    if tcp_flags & dpkt.tcp.TH_CWR:
        ret = ret + "C"

    return ret


def parse_TCP_from_IP(traffic_data_Ether_IP: list[tuple[float, dpkt.ip.IP]]) -> list[tuple[float, tuple[bytes, bytes, int, int], dpkt.tcp.TCP]]:
    # ts, dpkt.ip.IP
    traffic_data_Ether_IP_TCP: list[tuple[float, tuple[bytes, bytes, int, int], dpkt.tcp.TCP]] = []
    with Progress() as progress:
        packets_progress = progress.add_task("[green]Scaning for TCP layer packets...", total=len(traffic_data_Ether_IP))
        for ts, buf in traffic_data_Ether_IP:
            if isinstance(buf.data, dpkt.tcp.TCP):
                ip_src = cast(bytes, buf.src)  # type: ignore
                ip_dst = cast(bytes, buf.dst)  # type: ignore
                port_src = cast(int, buf.data.sport)  # type: ignore
                port_dst = cast(int, buf.data.dport)  # type: ignore
                traffic_data_Ether_IP_trip = (ip_src, ip_dst, port_src, port_dst)
                traffic_data_Ether_IP_TCP.append((ts, traffic_data_Ether_IP_trip, buf.data))
            else:
                logging.debug(f"Found non-TCP-layer data!")
                logging.debug(f"Non-TCP-layer data's ts: {ts}")
            progress.update(packets_progress, advance=1)
    logging.info(f"Valid TCP packets: {len(traffic_data_Ether_IP_TCP)}")
    # ts, (ip_src, ip_dst, port_src, port_dst), dpkt.tcp.TCP
    return traffic_data_Ether_IP_TCP


def parse_TCPSessions_from_TCP(traffic_data_Ether_IP_TCP: list[tuple[float, tuple[bytes, bytes, int, int], dpkt.tcp.TCP]]) -> defaultdict[tuple[bytes, bytes, int, int], bytes]:
    # Connections with current buffer
    sessions: defaultdict[tuple[bytes, bytes, int, int], bytes] = defaultdict(bytes)
    ended_sessions: set[tuple[bytes, bytes, int, int]] = set()
    with Progress() as progress:
        packets_progress = progress.add_task("[green]Scaning for raw packets...", total=len(traffic_data_Ether_IP_TCP))
        for ts, traffic_data_Ether_IP_trip, tcp in traffic_data_Ether_IP_TCP:
            # TODO Check if it is a FIN, if so end the connection
            tcp_flags = cast(int, tcp.flags)  # type: ignore
            tcp_flags = tcp_flag_detect(tcp_flags)

            if 'S' in tcp_flags:
                # Handle SYN: start of a new connection or a re-connection
                if traffic_data_Ether_IP_trip in sessions:
                    # logging.debug(f"Reconnection detected for {traffic_data_Ether_IP_trip}. Resetting session data.")
                    sessions[traffic_data_Ether_IP_trip] = tcp.data  # Reset session data
            else:
                if traffic_data_Ether_IP_trip in sessions:
                    sessions[traffic_data_Ether_IP_trip] += tcp.data
                else:
                    sessions[traffic_data_Ether_IP_trip] = tcp.data
            progress.update(packets_progress, advance=1)
    progress.stop()
    logging.info(f"Valid TCPSessions: {len(sessions)}")
    # (ip_src, ip_dst, port_src, port_dst), TCPSession_data
    return sessions
