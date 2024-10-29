import gzip
import socket
import logging
from collections import defaultdict
from rich.progress import Progress


def parse_http_request(payload: str | bytes) -> str:
    if type(payload) == str:
        try:
            payload_operatpr = payload.split(" ", maxsplit=1)[0]
        except:
            return ""
        match payload_operatpr:
            case "GET":
                return "GET"
            case "POST":
                return "POST"
            case "PUT":
                return "PUT"
            case "DELETE":
                return "DELETE"
            case "PATCH":
                return "PATCH"
            case "HEAD":
                return "HEAD"
            case "OPTIONS":
                return "OPTIONS"
            case "PROPFIND":
                return "PROPFIND"
            case _:
                return ""
    elif type(payload) == bytes:
        try:
            payload_operatpr = payload.split(b" ", maxsplit=1)[0].decode()
        except:
            return ""
        match payload.split(b" ", maxsplit=1)[0].decode():
            case "GET":
                return "GET"
            case "POST":
                return "POST"
            case "PUT":
                return "PUT"
            case "DELETE":
                return "DELETE"
            case "PATCH":
                return "PATCH"
            case "HEAD":
                return "HEAD"
            case "OPTIONS":
                return "OPTIONS"
            case "PROPFIND":
                return "PROPFIND"
            case _:
                return ""
    else:
        return ""


def parse_http_response(payload: str | bytes) -> tuple[str, int]:
    if type(payload) == str:
        try:
            [protocol_version, status_code] = payload.split(" ", maxsplit=2)[:2]
            return protocol_version, int(status_code)
        except:
            return "", -1
    elif type(payload) == bytes:
        try:
            [protocol_version, status_code] = payload.split(b" ", maxsplit=2)[:2]
            protocol_version = protocol_version.decode(errors="ignore")
            status_code = status_code.decode(errors="ignore")
            return protocol_version, int(status_code)
        except:
            return "", -1
    else:
        return "", -1


def detect_http_type(payload: str | bytes) -> tuple[str, str] | tuple[str, tuple[str, int]] | None:
    if parse_http_request(payload) != "":
        return "request", parse_http_request(payload)
    elif parse_http_response(payload) != ("", -1):
        return "response", parse_http_response(payload)
    else:
        return None


def parse_HTTPSessions_from_TCPSessions(traffic_data_TCPSessions: defaultdict[tuple[bytes, bytes, int, int], bytes]) -> tuple[defaultdict[tuple[bytes, bytes, int, int], list[bytes]], defaultdict[tuple[bytes, bytes, int, int], list[bytes]]]:
    http_requests: defaultdict[tuple[bytes, bytes, int, int], list[bytes]] = defaultdict(list)
    http_responses: defaultdict[tuple[bytes, bytes, int, int], list[bytes]] = defaultdict(list)
    with Progress() as progress:
        packets_progress = progress.add_task("[green]Scanning for HTTPSessions...", total=len(traffic_data_TCPSessions))
        # traffic_data_Ether_IP_trip -> session_id
        for session_id in traffic_data_TCPSessions.keys():
            stream = traffic_data_TCPSessions[session_id]
            info = detect_http_type(stream)
            if info == None:
                session_id_invaild = (socket.inet_ntop(socket.AF_INET, session_id[0]), socket.inet_ntop(socket.AF_INET, session_id[1]), session_id[2], session_id[3])
                logging.debug(f"Invaild HTTP session: {session_id_invaild}")
                continue
            elif info[0] == "request":
                http_requests[session_id].append(stream)
            elif info[0] == "response":
                ip_src, ip_dst, port_src, port_dst = session_id
                reverse_session_id = (ip_dst, ip_src, port_dst, port_src)
                http_responses[reverse_session_id].append(stream)
            progress.update(packets_progress, advance=1)
    logging.info(f"HTTP request packets quantity: {len(http_requests)}")
    logging.info(f"HTTP response packets quantity: {len(http_responses)}")
    return http_requests, http_responses


def parse_matched_HTTPSessions(http_requests: defaultdict[tuple[bytes, bytes, int, int], list[bytes]], http_responses: defaultdict[tuple[bytes, bytes, int, int], list[bytes]]) -> list[tuple[tuple[bytes, bytes, int, int], bytes, bytes]]:
    matched_sessions: list[tuple[tuple[bytes, bytes, int, int], bytes, bytes]] = []
    for session_id, reqs in http_requests.items():
        if session_id in http_responses:
            try:
                responses = http_responses[session_id]
            except:
                logging.error(f"Unmatched HTTP request packets: {session_id}")
            for req in reqs:
                for res in responses:
                    matched_sessions.append((session_id, req, res))
    logging.info(f"Valid HTTP communication quantity: {len(matched_sessions)}")
    return matched_sessions


def parse_HTTP_response_headers(payload: bytes) -> tuple[bytes, bytes]:
    headerEnd = payload.find(b"\r\n\r\n")
    if headerEnd != -1:
        headerEnd += 4
        return payload[:headerEnd], payload[headerEnd:]
    elif payload.find(b"\n\n") != -1:
        headerEnd = payload.index(b"\n\n") + 2
        return payload[:headerEnd], payload[headerEnd:]
    else:
        logging.error(f"Headers and response not found!")
        logging.error(f"Raw payload:")
        logging.error(payload.decode(errors="ignore"))
        return b"", payload


def parse_http_chunked_response(payload: bytes) -> bytes:
    chunks = []
    chunkSizeEnd = payload.find(b"\n") + 1
    lineEndings = b"\r\n" if bytes([payload[chunkSizeEnd - 2]]) == b"\r" else b"\n"
    lineEndingsLength = len(lineEndings)
    while True:
        chunkSize = int(payload[:chunkSizeEnd], 16)
        if not chunkSize:
            break

        chunks.append(payload[chunkSizeEnd : chunkSize + chunkSizeEnd])
        payload = payload[chunkSizeEnd + chunkSize + lineEndingsLength :]
        chunkSizeEnd = payload.find(lineEndings) + lineEndingsLength
    return b"".join(chunks)


def parse_http_gzip_response(payload: bytes) -> bytes:
    if payload.startswith(b"\x1F\x8B"):
        return gzip.decompress(payload)
    else:
        return b""


def parse_HTTPSessions_decompress(matched_sessions: list[tuple[tuple[bytes, bytes, int, int], bytes, bytes]]) -> list[tuple[tuple[bytes, bytes, int, int], bytes, bytes]]:
    matched_sessions_decompress: list[tuple[tuple[bytes, bytes, int, int], bytes, bytes]] = []
    # (session_id, http_requests_data, http_responses_data)
    with Progress() as progress:
        packets_progress = progress.add_task("[green]Scanning for HTTP sessions...", total=len(matched_sessions))
        for session_id, req, res in matched_sessions:
            response_data_header, response_data_context = parse_HTTP_response_headers(res)
            response_data = b""
            response_data_header_list = [i for i in response_data_header.decode(errors="ignore").replace("\r\n", "\n").split("\n") if i != ""]
            response_data_header_dict: dict[str, str] = {}
            for i in response_data_header_list[1:]:
                header_key, header_value = i.split(": ")
                response_data_header_dict[header_key.strip()] = header_value.strip()
            if "chunked" in str(response_data_header_dict.get("Transfer-Encoding")):
                try:
                    response_data = parse_http_chunked_response(response_data_context)
                except:
                    session_id_invaild = (socket.inet_ntop(socket.AF_INET, session_id[0]), socket.inet_ntop(socket.AF_INET, session_id[1]), session_id[2], session_id[3])
                    logging.error(f"parse chunked failed {session_id_invaild}")
                    # logging.error(f"raw data:\n{response_data_context}")
                    continue
            if "gzip" in str(response_data_header_dict.get("Content-Encoding")):
                try:
                    response_data = parse_http_gzip_response(response_data)
                except:
                    logging.error(f"parse chunked failed")
                    logging.error(f"raw data:\n{response_data_context}")
            progress.update(packets_progress, advance=1)
            matched_sessions_decompress.append((session_id, req, response_data_header + response_data))
    logging.info(f"Valid HTTP communication quantity: {len(matched_sessions)}")
    return matched_sessions_decompress
