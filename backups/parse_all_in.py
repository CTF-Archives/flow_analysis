import logging
import dpkt
from rich.progress import Progress
from io import BufferedReader
from typing import cast, Type, Union

# slower than analysis by layers

class Parser_TCP_UDP_from_capture:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.reader_class: Union[Type[dpkt.pcap.Reader], Type[dpkt.pcapng.Reader], None] = None
        if file_path.endswith("pcap"):
            self.reader_class = dpkt.pcap.Reader
        elif file_path.endswith("pcapng"):
            self.reader_class = dpkt.pcapng.Reader
        else:
            logging.error("Unsupported file format. Only pcap and pcapng are supported.")
            exit()

    def parse_capture(self):
        assert self.reader_class is not None, "self.reader_class should be set in __init__"
        # ts, bytes
        traffic_data: list[tuple[float, bytes]] = []
        # ts, dpkt.ethernet.Ethernet
        traffic_data_Ether: list[tuple[float, dpkt.ethernet.Ethernet]] = []
        # ts, dpkt.ethernet.Ethernet
        traffic_data_Ether_IP: list[tuple[float, dpkt.ip.IP]] = []
        # ts, dpkt.tcp.TCP
        traffic_data_Ether_IP_TCP: list[tuple[float, tuple[bytes, bytes, int, int], dpkt.tcp.TCP]] = []
        # ts, dpkt.udp.UDP
        traffic_data_Ether_IP_UDP: list[tuple[float, tuple[bytes, bytes, int, int], dpkt.udp.UDP]] = []

        with Progress() as progress, open(self.file_path, "rb") as _f:
            logging.info("Calculating packets quantity...")
            _count = 0
            for ts, buf in self.reader_class(_f):
                _count += 1
            logging.info(f"Packets quantity: {_count}")
            _f.seek(0, 0)
            packets_progress = progress.add_task("[green]Scanning for packets...", total=_count)
            for _ts, buf in self.reader_class(_f):
                # fix type check
                ts = cast(float, _ts)
                traffic_data.append((ts, buf))
                # extract Ethernet
                try:
                    traffic_data_Ether.append((ts, dpkt.ethernet.Ethernet(buf)))
                except:
                    logging.debug(f"Found non-Ether-layer data!")
                    logging.debug(f"Non-Ether-layer data's ts: {ts}")
                    continue
                packet_Ether = dpkt.ethernet.Ethernet(buf)
                # extract IP
                if isinstance(packet_Ether.data, dpkt.ip.IP):
                    traffic_data_Ether_IP.append((ts, packet_Ether.data))
                else:
                    logging.debug(f"Found non-IP-layer data!")
                    logging.debug(f"Non-IP-layer data's ts: {ts}")
                    continue
                packet_Ether_IP = packet_Ether.data
                # extract TCP and UDP
                if isinstance(packet_Ether_IP.data, dpkt.tcp.TCP):
                    ip_src = cast(bytes, packet_Ether_IP.src)  # type: ignore
                    ip_dst = cast(bytes, packet_Ether_IP.dst)  # type: ignore
                    port_src = cast(int, packet_Ether_IP.data.sport)  # type: ignore
                    port_dst = cast(int, packet_Ether_IP.data.dport)  # type: ignore
                    traffic_data_Ether_IP_trip = (ip_src, ip_dst, port_src, port_dst)
                    traffic_data_Ether_IP_TCP.append((ts, traffic_data_Ether_IP_trip, packet_Ether_IP.data))
                elif isinstance(packet_Ether_IP.data, dpkt.udp.UDP):
                    ip_src = cast(bytes, packet_Ether_IP.src)  # type: ignore
                    ip_dst = cast(bytes, packet_Ether_IP.dst)  # type: ignore
                    port_src = cast(int, packet_Ether_IP.data.sport)  # type: ignore
                    port_dst = cast(int, packet_Ether_IP.data.dport)  # type: ignore
                    traffic_data_Ether_IP_trip = (ip_src, ip_dst, port_src, port_dst)
                    traffic_data_Ether_IP_UDP.append((ts, traffic_data_Ether_IP_trip, packet_Ether_IP.data))
                else:
                    logging.debug(f"Found non-TCP-layer data!")
                    logging.debug(f"Non-TCP-layer data's ts: {ts}")
                    continue
                progress.update(packets_progress, advance=1)
        logging.info(f"Valid raw packets: {len(traffic_data)}")
        logging.info(f"Valid Ether packets: {len(traffic_data_Ether)}")
        logging.info(f"Valid IP packets: {len(traffic_data_Ether_IP)}")
        logging.info(f"Valid TCP packets: {len(traffic_data_Ether_IP_TCP)}")
        logging.info(f"Valid UDP packets: {len(traffic_data_Ether_IP_UDP)}")


if __name__ == "__main__":
    from rich.logging import RichHandler

    logging.basicConfig(level="INFO", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()])
    capture_file = "./examples/output.pcap"
    capture_parser =  Parser_TCP_UDP_from_capture(capture_file) 
    capture_parser.parse_capture()
