
from scapy.packet import Packet
from scapy.layers.inet import IP
from pydivert import WinDivert

from src.network_interceptor.core.intercepted_packet import InterceptedPacket
from src.network_interceptor.core.interceptor import BaseInterceptor
from src.network_interceptor.core.config import InterceptionConfig

from src.network_interceptor.core.arch.windows.wd_intercepted_packet import WinDivertInterceptedPacket


class WinDivertInterceptor(BaseInterceptor):
    def __init__(self, config: InterceptionConfig):
        super().__init__(config)
        self._wd_filter: str = ""
        self._new_packet: Packet | None = None


    def _wrap_scapy_packet(self, pkt: Packet) -> InterceptedPacket:
        wrapped = WinDivertInterceptedPacket(pkt, self)
        return wrapped

    def parse_config(self):
        args = self.config.core_arguments
        if "windivert" not in args:
            raise ValueError("Cannot run the interceptor: 'windivert' argument not set!")

        wd_config = args["windivert"]
        if "filter" not in wd_config:
            raise ValueError("Cannot run the interceptor: 'filter' setting not set for 'windivert'")

        self._wd_filter = wd_config["filter"]


    def run(self):
        self.parse_config()
        with WinDivert(self._wd_filter) as wd:
            for pkt in wd:
                try:
                    scapy_packet = IP(pkt.raw.tobytes())
                    self._handle_packet(scapy_packet)

                    if not self._action_taken:
                        # The packet is accepted
                        wd.send(pkt)
                        continue

                    if self._new_packet is not None:
                        # The packet is replaced
                        # TODO: serialize the new packet into WinDivert format
                        wd.send(pkt)
                        continue

                    # The remaining case is "drop". It doesn't require special handling

                except OSError as e:
                    print(f"OS error: {e}")
                except RuntimeError as e:
                    print(f"Runtime error: {e}")
                except KeyboardInterrupt:
                    return
