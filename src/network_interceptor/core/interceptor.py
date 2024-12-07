
from scapy.packet import Packet
from scapy.layers.inet import TCP, UDP, IP

from config import InterceptionConfig, UDPMode, TCPMode
from intercepted_packet import InterceptedPacket, PacketInterceptedCallback
from tcp import TCPConnectionManager

class BaseInterceptor:
    def __init__(self, config: InterceptionConfig):
        self.config = config
        self._action_taken = False
        self._tcp_manager = TCPConnectionManager(self)

    def _wrap_scapy_packet(self, pkt: Packet) -> InterceptedPacket:
        raise NotImplemented

    def _handle_low_level_packet(self, pkt: Packet, callback: PacketInterceptedCallback):
        wrapped = self._wrap_scapy_packet(pkt)
        callback(wrapped)

    def _handle_tcp_high_level(self, pkt: Packet):
        self._tcp_manager.handle(pkt)

    def _handle_packet(self, pkt: Packet):
        self._action_taken = False

        if IP not in pkt:
            # ACCEPT
            return

        ip_layer: Packet = pkt[IP]
        if UDP in ip_layer:
            if self.config.upd_mode == UDPMode.Disabled:
                # ACCEPT
                return
            self._handle_low_level_packet(pkt, self.config.upd_action)
            return

        if TCP in ip_layer:
            if self.config.tcp_mode == TCPMode.Disabled:
                # ACCEPT
                return

            if self.config.tcp_mode == TCPMode.LowLevel:
                self._handle_low_level_packet(pkt, self.config.tcp_action)
            else:
                self._handle_tcp_high_level(pkt)

    def run(self):
        raise NotImplemented
