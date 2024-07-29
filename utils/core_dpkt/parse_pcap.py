import dpkt
import logging
from rich.progress import Progress


def dechunck_HTTP_response(file_data: bytes) -> bytes:
    chunks = []
    chunkSizeEnd = file_data.find(b"\n") + 1
    lineEndings = b"\r\n" if bytes([file_data[chunkSizeEnd - 2]]) == b"\r" else b"\n"
    lineEndingsLength = len(lineEndings)
    while True:
        chunkSize = int(file_data[:chunkSizeEnd], 16)
        if not chunkSize:
            break

        chunks.append(file_data[chunkSizeEnd : chunkSize + chunkSizeEnd])
        file_data = file_data[chunkSizeEnd + chunkSize + lineEndingsLength :]
        chunkSizeEnd = file_data.find(lineEndings) + lineEndingsLength
    return b"".join(chunks)


def split_HTTP_response(http_response_data: bytes) -> tuple[bytes, bytes]:
    # sourcery skip: use-named-expression
    headerEnd = http_response_data.find(b"\r\n\r\n")
    if headerEnd != -1:
        headerEnd += 4
        return http_response_data[:headerEnd], http_response_data[headerEnd:]
    elif http_response_data.find(b"\n\n") != -1:
        headerEnd = http_response_data.index(b"\n\n") + 2
        return http_response_data[:headerEnd], http_response_data[headerEnd:]
    else:
        logging.error(f"No headers and responses were found!")
        logging.error(f"Raw http response data:")
        logging.error(http_response_data.decode(errors="ignore"))
        return b"", http_response_data


def parse_pcap_file(pcap_file: str) -> list[tuple[float, bytes]]:
    traffic_data: list[tuple[float, bytes]] = []

    logging.info("Calculating packets quantity...")
    _count = 0
    with open(pcap_file, "rb") as _f:
        for ts, buf in dpkt.pcapng.Reader(_f):
            _count += 1
    logging.info(f"Packets quantity: {_count}")

    with Progress() as progress:
        packets_progress = progress.add_task("[green]Scaning for raw packets...", total=_count)
        with open(pcap_file, "rb") as _f:
            for ts, buf in dpkt.pcapng.Reader(_f):
                traffic_data.append((ts, buf))
                progress.update(packets_progress, advance=1)
    logging.info(f"Valid raw packets: {len(traffic_data)}")
    # ts, bytes
    return traffic_data
