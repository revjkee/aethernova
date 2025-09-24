import socket
import ssl
import threading
import logging
from typing import Optional, Dict, Any, Callable, Tuple
from uuid import uuid4
from core.logger import get_logger
from core.metrics import record_listener_event

logger = get_logger("Listener")

class ListenerInstance:
    def __init__(
        self,
        name: str,
        bind_ip: str,
        port: int,
        handler: Callable[[bytes, Tuple[str, int]], None],
        use_ssl: bool = False,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        reverse: bool = False
    ):
        self.id = str(uuid4())
        self.name = name
        self.bind_ip = bind_ip
        self.port = port
        self.handler = handler
        self.use_ssl = use_ssl
        self.certfile = certfile
        self.keyfile = keyfile
        self.reverse = reverse
        self.running = False
        self.thread = None
        self.socket = None

    def _wrap_ssl(self, sock: socket.socket) -> ssl.SSLSocket:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            return context.wrap_socket(sock, server_side=True)
        except Exception as e:
            logger.exception(f"SSL wrapping failed on {self.name}: {e}")
            raise

    def _handle_connection(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        try:
            logger.debug(f"[{self.name}] Connection from {client_address}")
            data = client_socket.recv(4096)
            if data:
                self.handler(data, client_address)
        except Exception as e:
            logger.exception(f"[{self.name}] Error handling connection: {e}")
        finally:
            client_socket.close()

    def _bind_loop(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.bind_ip, self.port))
            self.socket.listen(100)

            logger.info(f"[{self.name}] Listening on {self.bind_ip}:{self.port}")
            record_listener_event(self.name, "started")

            while self.running:
                try:
                    client_socket, client_address = self.socket.accept()
                    if self.use_ssl:
                        client_socket = self._wrap_ssl(client_socket)
                    threading.Thread(target=self._handle_connection, args=(client_socket, client_address), daemon=True).start()
                except Exception as e:
                    logger.warning(f"[{self.name}] Accept loop error: {e}")
        finally:
            if self.socket:
                self.socket.close()
            record_listener_event(self.name, "stopped")

    def start(self):
        if self.running:
            logger.warning(f"Listener {self.name} already running.")
            return
        self.running = True
        self.thread = threading.Thread(target=self._bind_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.socket.close()
        logger.info(f"Listener {self.name} stopped.")


class ListenerManager:
    def __init__(self):
        self.listeners: Dict[str, ListenerInstance] = {}

    def register_listener(self, config: Dict[str, Any], handler: Callable[[bytes, Tuple[str, int]], None]) -> str:
        name = config.get("name", f"listener-{uuid4().hex[:6]}")
        bind_ip = config["bind_ip"]
        port = config["port"]
        use_ssl = config.get("ssl", False)
        certfile = config.get("certfile")
        keyfile = config.get("keyfile")

        listener = ListenerInstance(
            name=name,
            bind_ip=bind_ip,
            port=port,
            handler=handler,
            use_ssl=use_ssl,
            certfile=certfile,
            keyfile=keyfile
        )

        listener.start()
        self.listeners[name] = listener
        return listener.id

    def stop_listener(self, name: str) -> bool:
        listener = self.listeners.get(name)
        if not listener:
            logger.warning(f"No listener found with name {name}")
            return False
        listener.stop()
        del self.listeners[name]
        return True

    def list_listeners(self) -> Dict[str, Any]:
        return {
            name: {
                "id": inst.id,
                "ip": inst.bind_ip,
                "port": inst.port,
                "ssl": inst.use_ssl,
                "running": inst.running
            }
            for name, inst in self.listeners.items()
        }
