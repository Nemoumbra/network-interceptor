
from scapy.packet import Packet

from network_interceptor.core.intercepted_packet import InterceptedPacket

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from network_interceptor.core.arch.linux.nfq_interceptor import NFQueueInterceptor


class NFQueueInterceptedPacket(InterceptedPacket):
    def __init__(self, scapy_packet: Packet, interceptor: 'NFQueueInterceptor'):
        super().__init__(scapy_packet)
        self._interceptor: NFQueueInterceptor = interceptor

    def accept(self):
        self._check_action_chosen()
        # It's really just for convenience's sake

    def drop(self):
        self._check_action_chosen()
        self._action_taken = True
        self._interceptor._action_taken = True

    def replace(self, new_packet: Packet):
        self._check_action_chosen()
        self._action_taken = True
        self._interceptor._action_taken = True
        self._interceptor._new_packet = new_packet
