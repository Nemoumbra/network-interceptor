
from scapy.packet import Packet
from scapy.sendrecv import sniff
from scapy.utils import PcapWriter

from pathlib import Path

from network_interceptor.core.intercepted_packet import InterceptedPacket
from network_interceptor.core.interceptor import BaseInterceptor
from network_interceptor.core.config import InterceptionConfig

from network_interceptor.core.pcap.pcap_intercepted_packet import PcapInterceptedPacket


class PcapInterceptor(BaseInterceptor):
    def __init__(self, config: InterceptionConfig):
        super().__init__(config)
        self._callback = self._make_callback()
        self._input_path: str = ""
        self._output_path: str = ""

        self._new_packet: Packet | None = None

        self._packet_list: list[Packet] = []

    def _make_callback(self):
        def callback(pkt: Packet):
            self._handle_packet(pkt)

            if not self._action_taken:
                # The packet is accepted
                self._packet_list.append(pkt)

            if self._new_packet is not None:
                # The packet is replaced
                self._packet_list.append(self._new_packet)

            # The remaining case is "drop". It doesn't require special handling

        return callback

    def _parse_config(self):
        args = self.config.core_arguments
        if "pcap" not in args:
            raise ValueError("Cannot run the interceptor: 'pcap' argument not set!")
        pcap_config = args["pcap"]

        if "input" not in pcap_config:
            raise ValueError("Cannot run the interceptor: 'input' setting not set for 'pcap'!")
        self._input_path = pcap_config["input"]

        if "output" not in pcap_config:
            raise ValueError("Cannot run the interceptor: 'output' setting not set for 'pcap'!")
        output = pcap_config["output"]

        if type(output) is not str:
            raise ValueError(f"Wrong type for the 'output' parameter: expected 'str', got '{type(output)}'!")
        self._output_path = output


    def _wrap_scapy_packet(self, pkt: Packet) -> InterceptedPacket:
        wrapped = PcapInterceptedPacket(pkt, self)
        return wrapped

    def _run_impl(self):
        # This returns on its own, because the input pcap file is finite
        sniff(
            offline=self._input_path,
            prn=self._callback,
        )

        with PcapWriter(self._output_path) as writer:
            writer.write(self._packet_list)
