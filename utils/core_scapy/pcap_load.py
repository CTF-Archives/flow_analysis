import logging
import os
import hashlib
import pickle
from collections import defaultdict

from utils.core_scapy.http_processing import parse_http_sessions


def calculate_file_hash(file_path: str, hash_type="sha1") -> str:
    hash_func = hashlib.new(hash_type)

    # 以二进制模式读取文件并计算哈希
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def pcap_file_load_to_http(pcap_file: str)-> tuple[defaultdict, defaultdict]:
    logging.info(f"Loading traffic package file: {pcap_file}")
    if os.path.isfile(pcap_file):
        pcap_file_nash = calculate_file_hash(pcap_file, "sha1")
        logging.info(f"Traffic package file SHA-1 hash: {pcap_file_nash}")
    else:
        logging.error(f"Traffic package file does not exist!")
        exit()
    logging.info(f"Loading traffic package file cache: {pcap_file_nash}.flow.http")
    if os.path.isfile(pcap_file_nash + ".flow.http"):
        with open(pcap_file_nash + ".flow.http", "rb") as f:
            http_requests, http_responses = pickle.load(f)
    else:
        logging.error(f"Cache file does not exist!")
        http_requests, http_responses = parse_http_sessions(pcap_file)
        with open(pcap_file_nash + ".flow.http", "wb") as f:
            pickle.dump((http_requests, http_responses), f)
    return http_requests, http_responses
