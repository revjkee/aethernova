import asyncio
import logging
import secrets
import time
from datetime import datetime
from typing import Dict

from testground.utils.crypto import generate_fake_tls_context
from testground.utils.behavior import simulate_c2_command_response

logger = logging.getLogger("C2StubEmulator")
logging.basicConfig(level=logging.INFO)

DEFAULT_PORT = 4443
MAX_SESSIONS = 32
SESSION_TIMEOUT = 600  # seconds

class C2Session:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_id: str):
        self.reader = reader
        self.writer = writer
        self.session_id = session_id
        self.created_at = time.time()
        self.command_state = "IDLE"

    async def handle(self):
        logger.info(f"[{self.session_id}] Session started.")
        try:
            while True:
                if time.time() - self.created_at > SESSION_TIMEOUT:
                    logger.warning(f"[{self.session_id}] Session timeout.")
                    break

                data = await self.reader.readline()
                if not data:
                    logger.info(f"[{self.session_id}] Client disconnected.")
                    break

                cmd = data.decode().strip()
                logger.debug(f"[{self.session_id}] Received: {cmd}")
                response = simulate_c2_command_response(cmd, self.command_state)
                self.command_state = response.get("state", self.command_state)
                await self.send(response.get("output", "ACK"))
        except Exception as e:
            logger.error(f"[{self.session_id}] Error: {e}")
        finally:
            self.writer.close()
            await self.writer.wait_closed()
            logger.info(f"[{self.session_id}] Session closed.")

    async def send(self, message: str):
        self.writer.write(f"{message}\n".encode())
        await self.writer.drain()


class C2StubServer:
    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.sessions: Dict[str, C2Session] = {}

    async def start(self):
        ssl_context = generate_fake_tls_context()

        server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
            ssl=ssl_context
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f"C2StubServer running on {addrs}")
        async with server:
            await server.serve_forever()

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if len(self.sessions) >= MAX_SESSIONS:
            logger.warning("Too many active sessions. Rejecting new connection.")
            writer.write(b"ERROR: Server busy.\n")
            await writer.drain()
            writer.close()
            return

        session_id = secrets.token_hex(8)
        session = C2Session(reader, writer, session_id)
        self.sessions[session_id] = session
        await session.handle()
        del self.sessions[session_id]

if __name__ == "__main__":
    asyncio.run(C2StubServer().start())
