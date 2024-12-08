
from scapy.packet import Packet
from scapy.layers.inet import IP

from network_interceptor.core.intercepted_packet import InterceptedPacket
from network_interceptor.core.interceptor import BaseInterceptor
from network_interceptor.core.config import InterceptionConfig

from network_interceptor.core.arch.linux.nfq_intercepted_packet import NFQueueInterceptedPacket

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet as NFQPacket

from collections.abc import Callable


class NFQueueInterceptor(BaseInterceptor):
    def __init__(self, config: InterceptionConfig):
        super().__init__(config)
        self._callback: Callable[[NFQPacket], None] = self._make_callback()
        self._queue_num: int = 0
        self._new_packet: Packet | None = None

    def _make_callback(self):
        def callback(packet: NFQPacket):
            scapy_packet = IP(packet.get_payload())
            self._handle_packet(scapy_packet)

            if not self._action_taken:
                # The packet is accepted
                packet.accept()
                return

            if self._new_packet is not None:
                # The packet is replaced
                new_bytes = self._new_packet.build()
                packet.set_payload(new_bytes)
                packet.accept()
                return

            # The remaining case is "drop".
            packet.drop()
            return

        return callback

    def _wrap_scapy_packet(self, pkt: Packet) -> InterceptedPacket:
        wrapped = NFQueueInterceptedPacket(pkt, self)
        return wrapped

    def _parse_config(self):
        args = self.config.core_arguments
        if "nfqueue" not in args:
            raise ValueError("Cannot run the interceptor: 'nfqueue' argument not set!")

        nfq_config = args["nfqueue"]
        if "queue_num" not in nfq_config:
            raise ValueError("Cannot run the interceptor: 'queue_num' setting not set for 'nfqueue'")

        self._queue_num = nfq_config["queue_num"]

    # TODO:
    def _run_impl(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(self._queue_num, self._callback)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
        nfqueue.unbind()
