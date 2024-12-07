
from scapy.packet import Packet

from src.network_interceptor.core.intercepted_packet import InterceptedPacket
from src.network_interceptor.core.interceptor import BaseInterceptor
from src.network_interceptor.core.config import InterceptionConfig

from src.network_interceptor.core.arch.linux.nfq_intercepted_packet import NFQueueInterceptedPacket

class NFQueueInterceptor(BaseInterceptor):
    def __init__(self, config: InterceptionConfig):
        super().__init__(config)

    def _wrap_scapy_packet(self, pkt: Packet) -> InterceptedPacket:
        wrapped = NFQueueInterceptedPacket(pkt, self)
        return wrapped

    def parse_config(self):
        pass

    # TODO:
    def run(self):
        self.parse_config()