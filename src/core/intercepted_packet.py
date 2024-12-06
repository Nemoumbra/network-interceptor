
from collections.abc import Callable

from scapy.packet import Packet

class InterceptedPacket:
    def __init__(self, scapy_packet: Packet):
        self._packet = scapy_packet

    def as_scapy(self):
        return self._packet

    def accept(self):
        raise NotImplemented

    def drop(self):
        raise NotImplemented

    def replace(self, new_packet: Packet):
        raise NotImplemented


PacketInterceptedCallback = Callable[[InterceptedPacket], None]
