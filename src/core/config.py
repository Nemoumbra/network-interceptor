
from enum import Enum, auto


class UDPMode(Enum):
    Disabled = auto()
    Default = auto()


class TCPMode(Enum):
    Disabled = auto()
    LowLevel = auto()
    HighLevel = auto()


class InterceptionConfig:
    def __init__(self):
        self.core_arguments: dict = {}
        self.upd_mode: UDPMode = UDPMode.Disabled
        self.tcp_mode: TCPMode = TCPMode.Disabled
        # TODO
