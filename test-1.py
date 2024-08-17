# injection_path = "/rest/products/search?"
# injection_arg = "q"
# injection_success_res = "apple_juice"

# # ts, bytes
# traffic_data = parse_capture_file(capture_file)
# try:
#     assert(traffic_data)
# except:
#     logging.error("Parse capture file error!")
#     exit()
# # ts, dpkt.ethernet.Ethernet
# traffic_data_Ether = parse_Ether_from_traffic(traffic_data)
# # ts, dpkt.ip.IP
# traffic_data_Ether_IP = parse_IP_from_Ether(traffic_data_Ether)
# # ts, (ip_src, ip_dst, port_src, port_dst), dpkt.tcp.TCP
# traffic_data_Ether_IP_TCP = parse_TCP_from_IP(traffic_data_Ether_IP)
# # (ip_src, ip_dst, port_src, port_dst), TCPSession_data
# traffic_data_TCPSessions = parse_TCPSessions_from_TCP(traffic_data_Ether_IP_TCP)

# # parse http
# traffic_data_http_requests, traffic_data_http_responses = parse_HTTPSessions_from_TCPSessions(traffic_data_TCPSessions)
# traffic_data_matched_HTTPSessions = parse_matched_HTTPSessions(traffic_data_http_requests, traffic_data_http_responses)
# # Handling chunck encoding and gzip compression
# traffic_data_matched_HTTPSessions = parse_HTTPSessions_decompress(traffic_data_matched_HTTPSessions)

# inject_analyzer = SQL_injection_analyzer()
# with Progress() as progress:
#     packets_progress = progress.add_task("[green]Scanning for SQL injection...", total=len(traffic_data_matched_HTTPSessions))
#     for session_id, req, res in traffic_data_matched_HTTPSessions:
#         if res.startswith(b"HTTP/1.1 200"):
#             request_data_path = req.decode(errors="ignore").replace("\r\n", "\n").split("\n")[0].split(" ")[1]
#             response_data = res.decode(errors="ignore").replace("\r\n", "\n")

#             # 检测是否为注入点路径
#             if request_data_path.startswith(injection_path):
#                 # logging.debug(f"Request url:\n{request_data_path}")
#                 req_data_url_arg = {}
#                 for i in request_data_path.replace(injection_path, "").split("&"):
#                     i = i.split("=")
#                     req_data_url_arg[i[0]] = unquote(i[1])
#                 req_data_inject_payload = unquote(request_data_path).replace(injection_path, "")
#                 # 尝试提取sql注入参数
#                 injection_payload = None
#                 try:
#                     # table_name, key_name, injection_index, operator, compare_ascii
#                     injection_payload = inject_analyzer.sql_injection_payload_extract(str(req_data_url_arg.get(injection_arg)))
#                 except:
#                     injection_payload = None
#                     pass
#                 if injection_payload and injection_success_res in response_data:
#                     # logging.debug(injection_payload)
#                     inject_analyzer.sql_injection_data_extract(injection_payload)
#                     injection_payload = None
#         progress.update(packets_progress, advance=1)
# # 提取注入得到的数据
# injection_data = inject_analyzer.sql_injection_data_read()
# for table in injection_data.keys():
#     for key in injection_data[table].keys():
#         injection_data_index_list = [int(i) for i in list(injection_data[table][key].keys())]
#         injection_data_index_list.sort()
#         injection_data_key = ""
#         for i in injection_data_index_list:
#             injection_data_key += chr(int(injection_data[table][key][i][0]))
#         logging.info(f"table: {table}\tkey: {key}\tdata: {injection_data_key}")
