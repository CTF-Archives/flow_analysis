import logging
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from rich.logging import RichHandler
from collections import defaultdict
from rich.progress import Progress
from time import sleep
from scapy import 