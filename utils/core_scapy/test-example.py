import json
import logging
from time import sleep
from urllib.parse import unquote
from collections import defaultdict
from scapy.packet import Raw
from rich.logging import RichHandler
from rich.progress import Progress
from rich.logging import RichHandler

from utils.core_scapy.pcap_load import pcap_file_load_to_http
from utils.core_scapy.http_processing import match_http_sessions
from utils.core_injection_analyzer.sql_injection import SQL_injection_analyzer

logging.basicConfig(level="INFO", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()])


if __name__ == "__main__":

    pcap_file = "./output.pcap"

    injection_path = "/rest/products/search?"

    injection_arg = "q"

    injection_success_res = "success"

    http_requests, http_responses = pcap_file_load_to_http(pcap_file)
    matched_sessions = match_http_sessions(http_requests, http_responses)

    logging.info("Scaning for SQL injection...")

    inject_analyzer = SQL_injection_analyzer()

    for req, res in matched_sessions:
        # logging.info(req[Raw].load.decode(errors="ignore"))
        # logging.info(res[Raw].load.decode(errors="ignore"))
        # 提取请求包和返回包
        req_data = str(req[Raw].load.decode(errors="ignore")).split("\n")
        res_data = str(res[Raw].load.decode(errors="ignore")).split("\n")
        req_data_path = [i for i in req_data[0].split(" ") if i != ""][1]
        res_data_status_code = [i for i in res_data[0].split(" ") if i != ""][1]
        res_data_context = res_data[-1]

        # 检测是否为注入点路径
        if req_data_path.startswith(injection_path):
            logging.debug(f"Request url:\n{req_data_path}")
            req_data_url_arg = {}
            for i in req_data_path.split("&"):
                i = i.replace(injection_path, "").split("=")
                req_data_url_arg[i[0]] = unquote(i[1])
            req_data_inject_payload = unquote(req_data_path).replace(injection_path, "")
            logging.debug(f"Response status code: {res_data_status_code}")
            logging.debug(f"SQL injection payload:\n{req_data_url_arg}")
            # 尝试提取sql注入参数
            injection_payload = None
            try:
                # table_name, key_name, injection_index, operator, compare_ascii
                injection_payload = inject_analyzer.sql_injection_payload_extract(str(req_data_url_arg.get(injection_arg)))
            except:
                injection_payload = None
                pass
            if injection_payload and res_data_context == '{"status":"success","data":[]}':
                logging.debug(injection_payload)
                inject_analyzer.sql_injection_data_extract(injection_payload)
                injection_payload = None
    # 提取注入得到的数据
    injection_data = inject_analyzer.sql_injection_data_read()
    logging.debug(json.dumps(injection_data, indent=4, ensure_ascii=False))
    for table in injection_data.keys():
        for key in injection_data[table].keys():
            injection_data_index = [int(i) for i in list(injection_data[table][key].keys())]
            injection_data_index.sort()
            injection_data_key = ""
            for i in injection_data_index:
                injection_data_key += chr(int(injection_data[table][key][str(i)]))
            logging.info(f"table: {table}\tkey: {key}\tdata: {injection_data_key}")
