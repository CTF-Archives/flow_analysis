import dpkt
import logging
from typing import Union, Type, cast
from rich.progress import Progress


def _extract_packets(
    pcap_file: str,
    reader_class: Union[Type[dpkt.pcap.Reader], Type[dpkt.pcapng.Reader]],
) -> tuple[int, list[tuple[float, bytes]]]:
    """通用解析函数，支持 pcap 和 pcapng 格式

    Args:
        pcap_file (str): pcap 或 pcapng 文件路径
        reader_class (dpkt.pcap.Reader | dpkt.pcapng.Reader): Reader 类

    Returns:
        tuple[int, list[tuple[float, bytes]]]:
            int: Physical Layer Protocol ID
            list[tuple[float, bytes]]:
                - float: packet time
                - bytes: packet raw data
    """
    packets = []
    with Progress() as progress, open(pcap_file, "rb") as _f:
        # 计算原始包数量
        logging.info("Calculating raw packets quantity...")
        _count = sum(1 for _ in reader_class(_f))
        logging.info(f"Packets quantity: {_count}")
        # 重置文件指针
        _f.seek(0, 0)
        packets_progress = progress.add_task(
            "[green]Scanning for raw packets...", total=_count
        )
        for ts, buf in reader_class(_f):
            packets.append((ts, buf))
            progress.update(packets_progress, advance=1)
        _f.seek(0, 0)
        data_link_type = cast(int, reader_class(_f).datalink())
    logging.info(f"Physical Layer Protocol ID: {data_link_type}")
    logging.info(f"Valid raw packets: {len(packets)}")
    # ts, bytes
    return data_link_type, packets


def parse_capture_file(file_path: str) -> tuple[int, list[tuple[float, bytes]]]:
    """从 pcap 或 pcapng 文件中解析原始数据包

    Args:
        pcap_file (str): pcap 或 pcapng 流量包文件

    Returns:
        traffic_data: tuple[int, list[tuple[float, bytes]]]:
            int: Physical Layer Protocol ID
            list[tuple[float, bytes]]:
                - float: packet time
                - bytes: packet raw data
    """
    if file_path.endswith("pcap"):
        return _extract_packets(file_path, dpkt.pcap.Reader)
    elif file_path.endswith("pcapng"):
        return _extract_packets(file_path, dpkt.pcapng.Reader)
    else:
        logging.error(f"Unsupported file format: {file_path}")
        exit()
