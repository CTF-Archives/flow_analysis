import logging
from rich.logging import RichHandler
from utils.core_dpkt import *
from utils.core_injection_analyzer.sql_injection import SQL_injection_analyzer

from utils.core_scapy.parse_capture import parse_capture_file
from utils.core_scapy.parse_layer_Physical import parse_layer_Physical


# for debug
logging.basicConfig(level="NOTSET", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()])
# for normal running
logging.basicConfig(level="INFO", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()])


if __name__ == "__main__":

    capture_file = "./examples/Kerberoasting.pcapng"

    # data_link_type, list[(pkt_data, pkt_metadata), ...]
    data_link_type, traffic_data = parse_capture_file(capture_file)
    traffic_data = parse_layer_Physical(data_link_type, traffic_data)
    print(1)