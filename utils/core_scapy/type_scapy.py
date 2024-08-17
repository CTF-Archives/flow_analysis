import collections

PacketMetadata = collections.namedtuple("PacketMetadata", ["sec", "usec", "wirelen", "caplen"])