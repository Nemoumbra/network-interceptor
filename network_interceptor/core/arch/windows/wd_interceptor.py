
from scapy.packet import Packet
from scapy.layers.inet import IP
from pydivert import WinDivert
from pydivert import Packet as WDPacket

from network_interceptor.core.intercepted_packet import InterceptedPacket
from network_interceptor.core.interceptor import BaseInterceptor
from network_interceptor.core.config import InterceptionConfig

from network_interceptor.core.arch.windows.wd_intercepted_packet import WinDivertInterceptedPacket


class WinDivertInterceptor(BaseInterceptor):
    def __init__(self, config: InterceptionConfig):
        super().__init__(config)
        self._wd_filter: str = ""
        self._new_packet: Packet | None = None


    def _wrap_scapy_packet(self, pkt: Packet) -> InterceptedPacket:
        wrapped = WinDivertInterceptedPacket(pkt, self)
        return wrapped

    def _parse_config(self):
        args = self.config.core_arguments
        if "windivert" not in args:
            raise ValueError("Cannot run the interceptor: 'windivert' argument not set!")

        wd_config = args["windivert"]
        if "filter" not in wd_config:
            raise ValueError("Cannot run the interceptor: 'filter' setting not set for 'windivert'")

        self._wd_filter = wd_config["filter"]

        # Do some validation here...
        res, pos, msg = WinDivert.check_filter(self._wd_filter)
        if res:
            return
        raise ValueError(
            f"Wrong 'filter' setting format for 'windivert': {msg}. Error is at {pos} ('{self._wd_filter[pos:]}')"
        )

    def _build_new_packet(self, old_packet: WDPacket, new_packet: Packet):
        pkt = WDPacket(new_packet.build(), old_packet.interface, old_packet.direction)
        return pkt

    def _run_impl(self):
        try:
            with WinDivert(self._wd_filter) as wd:
                for pkt in wd:
                    scapy_packet = IP(pkt.raw.tobytes())
                    old_size = len(scapy_packet)
                    self._handle_packet(scapy_packet)

                    if not self._action_taken:
                        # The packet is accepted
                        wd.send(pkt, True)
                        continue

                    if self._new_packet is not None:
                        # The packet is replaced
                        new_size = len(self._new_packet)
                        new_pkt = self._build_new_packet(pkt, self._new_packet)
                        wd.send(new_pkt, True)
                        continue

                    # The remaining case is "drop". It doesn't require special handling

        except KeyboardInterrupt:
            return
