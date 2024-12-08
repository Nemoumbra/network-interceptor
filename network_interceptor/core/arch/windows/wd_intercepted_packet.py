
from scapy.packet import Packet

from network_interceptor.core.intercepted_packet import InterceptedPacket

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from network_interceptor.core.arch.windows.wd_interceptor import WinDivertInterceptor


class WinDivertInterceptedPacket(InterceptedPacket):
    def __init__(self, scapy_packet: Packet, interceptor: 'WinDivertInterceptor'):
        super().__init__(scapy_packet)
        self._interceptor: WinDivertInterceptor = interceptor

    # TODO:
    def accept(self):
        self._check_action_chosen()
        # It's really just for convenience's sake, no need to do anything here

    def drop(self):
        self._check_action_chosen()
        self._action_taken = True
        self._interceptor._action_taken = True

    def replace(self, new_packet: Packet):
        self._check_action_chosen()
        self._action_taken = True
        self._interceptor._action_taken = True
        self._interceptor._new_packet = new_packet
