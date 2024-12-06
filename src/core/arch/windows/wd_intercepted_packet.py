
from scapy.packet import Packet

from src.core.intercepted_packet import InterceptedPacket

from src.core.arch.windows.wd_interceptor import WinDivertInterceptor


class WinDivertInterceptedPacket(InterceptedPacket):
    def __init__(self, scapy_packet: Packet, interceptor: WinDivertInterceptor):
        super().__init__(scapy_packet)
        self._interceptor = interceptor

    # TODO:
    def accept(self):
        self._check_action_chosen()
        # It's really just for convenience's sake

    def drop(self):
        self._check_action_chosen()
        self._action_taken = True

    def replace(self, new_packet: Packet):
        self._check_action_chosen()
        self._action_taken = True
        self._interceptor._new_packet = new_packet
