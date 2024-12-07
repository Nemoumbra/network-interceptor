
from dataclasses import dataclass
from enum import Enum, auto

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP

from src.network_interceptor.core.interceptor import BaseInterceptor


@dataclass(frozen=True)
class Peer:
    ip: str = ""
    port: str = ""


# TODO: support the FIN handshake and/or RST
class TCPConnectionState(Enum):
    DoNotTouch = auto()
    SynSent = auto()
    AckSent = auto()
    Established = auto()


@dataclass
class TCPConnection:
    initiator: Peer
    other: Peer
    state: TCPConnectionState

    dropped_left: int
    dropped_right: int


    def __repr__(self):
        return f"{self.initiator.ip}:{self.initiator.port} -> {self.other.ip}:{self.other.port}"


class TCPConnectionManager:
    def __init__(self, interceptor: BaseInterceptor):
        self._connections: dict[Peer, TCPConnection] = {}
        self._interceptor: BaseInterceptor = interceptor

    def _find_connection(self, src_peer: Peer, dst_peer: Peer):
        if src_peer in self._connections:
            return True
        if dst_peer in self._connections:
            return False
        return None

    def _handle_new_connection(self, packet: Packet, src_peer: Peer, dst_peer: Peer):
        connection = TCPConnection(src_peer, dst_peer, TCPConnectionState.DoNotTouch, 0, 0)
        flags = packet[TCP].flags
        # TODO: maybe use an integer representation to test for SYN?
        if flags.S:
            # If it's not SYN, we ignore this connection
            connection.state = TCPConnectionState.SynSent

        self._connections[src_peer] = connection

    @staticmethod
    def _handle_syn_sent(packet: Packet, connection: TCPConnection):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        flags = tcp_layer.flags
        if not (flags.S and flags.A):
            # That's not what we were expecting.
            connection.state = TCPConnectionState.DoNotTouch
            return
        # It must be addressed to the initiator
        if connection.initiator.ip != ip_layer.dst or connection.initiator.port != tcp_layer.dport:
            connection.state = TCPConnectionState.DoNotTouch
            return
        # TODO: maybe verify that 'ack == initiator's seq + 1'?
        connection.state = TCPConnectionState.AckSent

    @staticmethod
    def _handle_ack_sent(packet: Packet, connection: TCPConnection):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        flags = tcp_layer.flags
        if not flags.A:
            # That's not what we were expecting.
            connection.state = TCPConnectionState.DoNotTouch
            return
        # It must be coming from the initiator
        if connection.initiator.ip != ip_layer.src or connection.initiator.port != tcp_layer.sport:
            connection.state = TCPConnectionState.DoNotTouch
            return
        connection.state = TCPConnectionState.Established

        # TODO: maybe check for PSH flag here too?
        return

    def _handle_established(self, packet: Packet, connection: TCPConnection):
        # TODO
        pass

    def _handle_existing_connection(self, packet: Packet, connection: TCPConnection):
        match connection.state:
            case TCPConnectionState.DoNotTouch:
                # Don't interfere
                return
            case TCPConnectionState.SynSent:
                self._handle_syn_sent(packet, connection)
            case TCPConnectionState.AckSent:
                self._handle_ack_sent(packet, connection)
            case TCPConnectionState.Established:
                self._handle_established(packet, connection)

    def handle(self, packet: Packet):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        src_peer = Peer(src_ip, src_port)
        dst_peer = Peer(dst_ip, dst_port)

        res = self._find_connection(src_peer, dst_peer)
        if res is None:
            # It's a new connection!
            self._handle_new_connection(packet, src_peer, dst_peer)
            return

        connection = self._connections[src_peer if res else dst_peer]
        self._handle_existing_connection(packet, connection)

