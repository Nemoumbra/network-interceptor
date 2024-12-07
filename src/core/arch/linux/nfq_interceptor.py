
from scapy.packet import Packet

from src.core.intercepted_packet import InterceptedPacket
from src.core.interceptor import BaseInterceptor
from src.core.config import InterceptionConfig

from src.core.arch.linux.nfq_intercepted_packet import NFQueueInterceptedPacket

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