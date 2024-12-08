
from scapy.packet import Packet
from scapy.layers.inet import TCP, UDP, IP

from network_interceptor.core.config import InterceptionConfig, UDPMode, TCPMode
from network_interceptor.core.intercepted_packet import InterceptedPacket, PacketInterceptedCallback
from network_interceptor.core.tcp import TCPConnectionManager


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

    def _validate_callbacks(self):
        if self.config.upd_mode != UDPMode.Disabled and self.config.upd_action is None:
                raise ValueError(f"UDP action not set despite the mode being {self.config.upd_mode}")
        if self.config.tcp_mode != TCPMode.Disabled and self.config.tcp_action is None:
                raise ValueError(f"TCP action not set despite the mode being {self.config.tcp_mode}")

    def _parse_config(self):
        raise NotImplemented

    def _run_impl(self):
        raise NotImplemented

    def run(self):
        self._parse_config()
        self._validate_callbacks()
        self._run_impl()
