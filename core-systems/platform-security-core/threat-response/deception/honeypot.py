import logging
import threading
import socket
import time
from typing import List, Dict, Optional

class Honeypot:
    """
    Модуль Honeypot для ловли и анализа атак.
    Создает ловушку, имитирующую уязвимый сервис.
    """

    def __init__(self, listen_ip: str = "0.0.0.0", listen_ports: List[int] = None):
        self.listen_ip = listen_ip
        self.listen_ports = listen_ports or [22, 80, 443]
        self.logger = logging.getLogger("Honeypot")
        self.logger.setLevel(logging.INFO)
        self.servers = []
        self.active = False

    def start(self):
        self.active = True
        self.logger.info(f"Starting Honeypot on {self.listen_ip} ports {self.listen_ports}")
        for port in self.listen_ports:
            thread = threading.Thread(target=self._listen_on_port, args=(port,), daemon=True)
            thread.start()
            self.servers.append(thread)

    def stop(self):
        self.active = False
        self.logger.info("Stopping Honeypot...")

    def _listen_on_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.listen_ip, port))
                s.listen()
                self.logger.info(f"Honeypot listening on port {port}")
                while self.active:
                    s.settimeout(1.0)
                    try:
                        conn, addr = s.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        self._handle_connection(conn, addr, port)
        except Exception as e:
            self.logger.error(f"Error on port {port}: {e}")

    def _handle_connection(self, conn: socket.socket, addr: tuple, port: int):
        ip, client_port = addr
        self.logger.info(f"Connection attempt from {ip}:{client_port} on honeypot port {port}")

        try:
            # Простейшая имитация уязвимого сервиса с ответом
            welcome_message = f"220 Fake Service on port {port} ready\r\n"
            conn.sendall(welcome_message.encode())

            data = conn.recv(1024)
            if data:
                self.logger.info(f"Received data from {ip}:{client_port}: {data.decode(errors='ignore')}")
                # Можно добавить логику анализа данных
                response = "500 Command not recognized\r\n"
                conn.sendall(response.encode())
        except Exception as e:
            self.logger.error(f"Error handling connection from {ip}:{client_port}: {e}")

    def get_status(self) -> Dict[str, Optional[List[int]]]:
        return {
            "active": self.active,
            "listening_ports": self.listen_ports if self.active else None
        }
