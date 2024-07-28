import json
import socket
import logging
from urllib.parse import unquote
from collections import defaultdict
from rich.logging import RichHandler
from utils.core_dpkt.parse_pcap import parse_pcap_file
from utils.core_dpkt.parse_Ether import parse_Ether_from_traffic
from utils.core_dpkt.parse_IP import parse_IP_from_Ether
from utils.core_dpkt.parse_TCP import parse_TCP_from_IP, parse_TCPSessions_from_TCP
from utils.core_dpkt.parse_HTTP import parse_HTTPSessions_from_TCPSessions, parse_matched_HTTPSessions, parse_HTTP_response_headers, parse_http_chunked_response, parse_http_gzip_response
from utils.core_injection_analyzer.sql_injection import SQL_injection_analyzer

logging.basicConfig(level="NOTSET", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()])


if __name__ == "__main__":

    pcap_file = "./output.pcap"
    injection_path = "/rest/products/search?"
    injection_arg = "q"
    injection_success_res = "success"

    # ts, bytes
    traffic_data = parse_pcap_file(pcap_file)
    # ts, dpkt.ethernet.Ethernet
    traffic_data_Ether = parse_Ether_from_traffic(traffic_data)
    # ts, dpkt.ip.IP
    traffic_data_Ether_IP = parse_IP_from_Ether(traffic_data_Ether)
    # ts, (ip_src, ip_dst, port_src, port_dst), dpkt.tcp.TCP
    traffic_data_Ether_IP_TCP = parse_TCP_from_IP(traffic_data_Ether_IP)
    # https://blog.bramp.net/post/2010/01/10/follow-http-stream-with-decompression/
    # (ip_src, ip_dst, port_src, port_dst), TCPSession_data
    traffic_data_TCPSessions = parse_TCPSessions_from_TCP(traffic_data_Ether_IP_TCP)
    traffic_data_http_requests, traffic_data_http_responses = parse_HTTPSessions_from_TCPSessions(traffic_data_TCPSessions)
    traffic_data_matched_HTTPSessions = parse_matched_HTTPSessions(traffic_data_http_requests, traffic_data_http_responses)

    logging.info("Scaning for SQL injection...")
    from time import sleep

    inject_analyzer = SQL_injection_analyzer()
    for session_id, req, res in traffic_data_matched_HTTPSessions:
        if res.startswith(b"HTTP/1.1 200"):
            request_data = req.decode(errors="ignore").replace("\r\n", "\n")
            request_data_path = request_data.split("\n")[0].split(" ")[1]
            response_data_header, response_data_context = parse_HTTP_response_headers(res)
            response_data=b""
            response_data_status_code = int(response_data_header.split(b"\n")[0].split(b" ")[1].decode())
            response_data_header_list = [i for i in response_data_header.decode(errors="ignore").replace("\r\n", "\n").split("\n") if i != ""]
            response_data_header_dict: dict[str, str] = {}
            for i in response_data_header_list[1:]:
                header_key, header_value = i.split(": ")
                response_data_header_dict[header_key.strip()] = header_value.strip()
            if "chunked" in str(response_data_header_dict.get("Transfer-Encoding")):
                try:
                    response_data = parse_http_chunked_response(response_data_context)
                except:
                    logging.error(f"parse chunked failed")
                    logging.error(f"raw data:\n{response_data_context}")
            if "gzip" in str(response_data_header_dict.get("Content-Encoding")):
                try:
                    response_data = parse_http_gzip_response(response_data)
                except:
                    logging.error(f"parse chunked failed")
                    logging.error(f"raw data:\n{response_data_context}")
            response_data = response_data.decode(errors="ignore").replace("\r\n", "\n")

            # 检测是否为注入点路径
            if request_data_path.startswith(injection_path):
                # logging.debug(f"Request url:\n{request_data_path}")
                req_data_url_arg = {}
                for i in request_data_path.replace(injection_path, "").split("&"):
                    i = i.split("=")
                    req_data_url_arg[i[0]] = unquote(i[1])
                req_data_inject_payload = unquote(request_data_path).replace(injection_path, "")
                # 尝试提取sql注入参数
                injection_payload = None
                try:
                    # table_name, key_name, injection_index, operator, compare_ascii
                    injection_payload = inject_analyzer.sql_injection_payload_extract(str(req_data_url_arg.get(injection_arg)))
                except:
                    injection_payload = None
                    pass
                if injection_payload and "apple_juice" in response_data:
                    # logging.debug(injection_payload)
                    inject_analyzer.sql_injection_data_extract(injection_payload)
                    injection_payload = None
    # 提取注入得到的数据
    injection_data = inject_analyzer.sql_injection_data_read()
    for table in injection_data.keys():
        for key in injection_data[table].keys():
            injection_data_index_list = [int(i) for i in list(injection_data[table][key].keys())]
            injection_data_index_list.sort()
            injection_data_key = ""
            for i in injection_data_index_list:
                injection_data_key += chr(int(injection_data[table][key][i][0]))
            logging.info(f"table: {table}\tkey: {key}\tdata: {injection_data_key}")

