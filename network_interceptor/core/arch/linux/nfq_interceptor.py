
from scapy.packet import Packet

from network_interceptor.core.intercepted_packet import InterceptedPacket
from network_interceptor.core.interceptor import BaseInterceptor
from network_interceptor.core.config import InterceptionConfig

from network_interceptor.core.arch.linux.nfq_intercepted_packet import NFQueueInterceptedPacket

class NFQueueInterceptor(BaseInterceptor):
    def __init__(self, config: InterceptionConfig):
        super().__init__(config)

    def _wrap_scapy_packet(self, pkt: Packet) -> InterceptedPacket:
        wrapped = NFQueueInterceptedPacket(pkt, self)
        return wrapped

    def _parse_config(self):
        pass

    # TODO:
    def _run_impl(self):
        pass
