# phantommesh-core/node_network/mesh_discovery.py

import asyncio
import json
import logging
import random
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple, Set

DISCOVERY_PORT = 46464
MULTICAST_GROUP = "239.192.0.1"
ANNOUNCE_INTERVAL = 10
PEER_TIMEOUT = 60
MAX_PEERS = 128

logger = logging.getLogger("mesh_discovery")
logger.setLevel(logging.DEBUG)

class MeshNodeInfo:
    def __init__(self, node_id: str, ip: str, port: int, timestamp: float):
        self.node_id = node_id
        self.ip = ip
        self.port = port
        self.last_seen = timestamp

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "ip": self.ip,
            "port": self.port,
            "last_seen": self.last_seen
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MeshNodeInfo":
        return cls(
            node_id=data["node_id"],
            ip=data["ip"],
            port=data["port"],
            timestamp=data["last_seen"]
        )

class MeshDiscovery:
    def __init__(self, node_id: str, listen_port: int):
        self.node_id = node_id
        self.listen_port = listen_port
        self.peers: Dict[str, MeshNodeInfo] = {}
        self.blacklist: Set[str] = set()
        self.transport: Optional[asyncio.DatagramTransport] = None

    def _encode_announce(self) -> bytes:
        msg = {
            "type": "announce",
            "node_id": self.node_id,
            "port": self.listen_port,
            "timestamp": time.time()
        }
        return json.dumps(msg).encode("utf-8")

    def _decode_announce(self, data: bytes, addr: Tuple[str, int]) -> Optional[MeshNodeInfo]:
        try:
            msg = json.loads(data.decode())
            if msg.get("type") != "announce":
                return None
            ip = addr[0]
            port = int(msg["port"])
            nid = msg["node_id"]
            ts = float(msg["timestamp"])
            if nid == self.node_id or nid in self.blacklist:
                return None
            return MeshNodeInfo(nid, ip, port, ts)
        except Exception:
            return None

    def _purge_stale_peers(self):
        now = time.time()
        to_remove = [
            node_id for node_id, peer in self.peers.items()
            if (now - peer.last_seen) > PEER_TIMEOUT
        ]
        for node_id in to_remove:
            del self.peers[node_id]
            logger.info(f"Удалён устаревший узел: {node_id}")

    def get_active_peers(self) -> List[MeshNodeInfo]:
        self._purge_stale_peers()
        return list(self.peers.values())[:MAX_PEERS]

    async def _announce_loop(self):
        while True:
            if self.transport:
                self.transport.sendto(
                    self._encode_announce(),
                    (MULTICAST_GROUP, DISCOVERY_PORT)
                )
            await asyncio.sleep(ANNOUNCE_INTERVAL)

    def _process_packet(self, data: bytes, addr: Tuple[str, int]):
        peer_info = self._decode_announce(data, addr)
        if peer_info:
            self.peers[peer_info.node_id] = peer_info
            logger.debug(f"Обнаружен узел: {peer_info.node_id} @ {peer_info.ip}:{peer_info.port}")

    async def start(self):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", DISCOVERY_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: MeshDiscoveryProtocol(self),
            sock=sock
        )
        asyncio.create_task(self._announce_loop())

    def blacklist_node(self, node_id: str):
        self.blacklist.add(node_id)
        if node_id in self.peers:
            del self.peers[node_id]
        logger.warning(f"Узел занесён в чёрный список: {node_id}")

class MeshDiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, discovery: MeshDiscovery):
        self.discovery = discovery

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self.discovery._process_packet(data, addr)

