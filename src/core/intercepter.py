
import scapy

from config import InterceptionConfig

class Interceptor:
    def __init__(self, config: InterceptionConfig):
        self.config = config

