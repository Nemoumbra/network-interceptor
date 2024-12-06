
from scapy.packet import Packet
from scapy.layers.inet import TCP, UDP, IP

from config import InterceptionConfig, UDPMode, TCPMode
from intercepted_packet import InterceptedPacket

class  Interceptor:
    def __init__(self, config: InterceptionConfig):
        self.config = config

    def _wrap_scapy_packet(self, pkt: Packet) -> InterceptedPacket:
        raise NotImplemented

    def _handle_udp(self, pkt: Packet):
        raise NotImplemented

    def _handle_tcp_low_level(self, pkt: Packet):
        raise NotImplemented

    def _handle_tcp_high_level(self, pkt: Packet):
        raise NotImplemented

    def _handle_packet(self, pkt: Packet):
        if IP not in pkt:
            # ACCEPT
            return

        ip_layer: Packet = pkt[IP]
        if UDP in ip_layer:
            if self.config.upd_mode == UDPMode.Disabled:
                # ACCEPT
                return
            self._handle_udp(pkt)
            return

        if TCP in ip_layer:
            if self.config.tcp_mode == TCPMode.Disabled:
                # ACCEPT
                return

            if self.config.tcp_mode == TCPMode.LowLevel:
                self._handle_tcp_low_level(pkt)
            else:
                self._handle_tcp_high_level(pkt)

