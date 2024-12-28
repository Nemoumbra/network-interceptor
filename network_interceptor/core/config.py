
from enum import Enum, auto

from network_interceptor.core.intercepted_packet import PacketInterceptedCallback


class UDPMode(Enum):
    Disabled = auto()
    LowLevel = auto()


class TCPMode(Enum):
    Disabled = auto()
    LowLevel = auto()
    HighLevel = auto()


class InterceptionConfig:
    def __init__(self):
        self.core_arguments: dict = {}
        self.upd_mode: UDPMode = UDPMode.Disabled
        self.tcp_mode: TCPMode = TCPMode.Disabled
        self.upd_action: PacketInterceptedCallback | None = None
        self.tcp_action: PacketInterceptedCallback | None = None
