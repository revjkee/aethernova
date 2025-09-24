# phantommesh-core/tor_layer/obfs4_router.py

import asyncio
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional, Dict
from secrets import token_urlsafe

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

OBFS4_BRIDGE_TEMPLATE = """
Bridge obfs4 {ip}:{port} {fingerprint} cert={cert} iat-mode=0
"""

TORRC_TEMPLATE = """
RunAsDaemon 1
DataDirectory {data_dir}
Log notice stdout
ClientTransportPlugin obfs4 exec {obfs4_path}
UseBridges 1
{bridge_lines}
"""

logger = logging.getLogger("obfs4_router")
logger.setLevel(logging.DEBUG)

class Obfs4Bridge:
    def __init__(self, ip: str, port: int, fingerprint: str, cert: str):
        self.ip = ip
        self.port = port
        self.fingerprint = fingerprint
        self.cert = cert

    def to_torrc_line(self) -> str:
        return OBFS4_BRIDGE_TEMPLATE.strip().format(
            ip=self.ip,
            port=self.port,
            fingerprint=self.fingerprint,
            cert=self.cert
        )

class Obfs4Router:
    def __init__(self, obfs4_path: str = "/usr/bin/obfs4proxy", bridge_list: Optional[List[Obfs4Bridge]] = None):
        self.obfs4_path = obfs4_path
        self.bridge_list = bridge_list or []
        self.active_process: Optional[asyncio.subprocess.Process] = None
        self.data_dir = tempfile.mkdtemp(prefix="obfs4_router_")
        self.torrc_path = os.path.join(self.data_dir, "torrc")
        self.control_flags: Dict[str, bool] = {"running": False}

    def _write_torrc(self) -> None:
        bridge_lines = "\n".join(b.to_torrc_line() for b in self.bridge_list)
        config = TORRC_TEMPLATE.format(
            data_dir=self.data_dir,
            obfs4_path=self.obfs4_path,
            bridge_lines=bridge_lines
        )
        with open(self.torrc_path, "w") as f:
            f.write(config)
        logger.info(f"Wrote torrc to {self.torrc_path}")

    async def start(self) -> None:
        self._write_torrc()
        self.control_flags["running"] = True
        self.active_process = await asyncio.create_subprocess_exec(
            "tor", "-f", self.torrc_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        logger.info("Started TOR process with obfs4 bridges")

    async def monitor(self) -> None:
        if not self.active_process:
            logger.warning("No active TOR process to monitor")
            return
        stdout, stderr = await self.active_process.communicate()
        logger.info(f"TOR stdout:\n{stdout.decode()}")
        logger.error(f"TOR stderr:\n{stderr.decode()}")
        self.control_flags["running"] = False

    async def stop(self) -> None:
        if self.active_process and self.control_flags["running"]:
            self.active_process.terminate()
            await self.active_process.wait()
            logger.info("TOR process terminated")
        self.control_flags["running"] = False

    def cleanup(self) -> None:
        shutil.rmtree(self.data_dir, ignore_errors=True)
        logger.info(f"Cleaned up data directory {self.data_dir}")

    @staticmethod
    def parse_bridge_line(line: str) -> Optional[Obfs4Bridge]:
        pattern = r"Bridge obfs4 ([^:]+):(\d+) ([a-fA-F0-9]+) cert=([^ ]+) iat-mode=0"
        match = re.match(pattern, line.strip())
        if match:
            ip, port, fingerprint, cert = match.groups()
            return Obfs4Bridge(ip, int(port), fingerprint, cert)
        return None

    @staticmethod
    def generate_fingerprint_and_cert() -> (str, str):
        private_key = Ed25519PrivateKey.generate()
        pub_key = private_key.public_key()
        fingerprint = pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        cert = token_urlsafe(32)
        return fingerprint, cert

    def rotate_bridges(self, count: int = 3) -> None:
        self.bridge_list.clear()
        for _ in range(count):
            ip = f"192.168.{os.urandom(1)[0] % 255}.{os.urandom(1)[0] % 255}"
            port = 443
            fingerprint, cert = self.generate_fingerprint_and_cert()
            bridge = Obfs4Bridge(ip, port, fingerprint, cert)
            self.bridge_list.append(bridge)
        logger.info(f"Rotated bridges: {[b.ip for b in self.bridge_list]}")

    async def restart(self) -> None:
        await self.stop()
        self.rotate_bridges()
        await self.start()

async def run_router_loop():
    router = Obfs4Router()
    try:
        await router.start()
        await asyncio.sleep(15)  # Example uptime
        await router.restart()
        await asyncio.sleep(15)
    finally:
        await router.stop()
        router.cleanup()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_router_loop())
