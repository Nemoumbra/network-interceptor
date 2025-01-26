
from collections.abc import Callable

from scapy.packet import Packet

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from network_interceptor.core.interceptor import BaseInterceptor


class InterceptedPacket:
    def __init__(self, scapy_packet: Packet,  interceptor: 'BaseInterceptor'):
        self._packet = scapy_packet
        self._interceptor = interceptor

        self._action_chosen: bool = False

    def _check_action_chosen(self):
        if self._action_chosen:
            raise RuntimeError("Packet-intercepted action already chosen")
        self._action_chosen = True

    def as_scapy(self):
        return self._packet

    def accept(self):
        self._check_action_chosen()
        # It's really just for convenience's sake

    def drop(self):
        self._check_action_chosen()
        self._action_chosen = True
        self._interceptor._action_taken = True

    def replace(self, new_packet: Packet):
        self._check_action_chosen()
        self._action_chosen = True
        self._interceptor._action_taken = True
        self._interceptor._new_packet = new_packet


PacketInterceptedCallback = Callable[[InterceptedPacket], None]
