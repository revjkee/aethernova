# Синхронизация времени между агентами
# time_sync.py
# Модуль синхронизации времени между агентами в распределённой системе
# Используется протокол NTP-подобный с поправками, учитывает сетевые задержки и дрейф часов

import time
import threading
import socket
import struct

class TimeSyncError(Exception):
    pass

class TimeSyncClient:
    """
    Клиент для синхронизации времени с сервером.
    Использует UDP для минимальной задержки.
    """

    NTP_TIMESTAMP_DELTA = 2208988800  # Разница между эпохой 1900 и 1970

    def __init__(self, server_ip: str, server_port: int = 123):
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)

    def _build_request_packet(self) -> bytes:
        # NTP-запрос: 48 байт, первый байт - 0x1B (LI=0, VN=3, Mode=3)
        return b'\x1b' + 47 * b'\0'

    def _parse_response(self, data: bytes) -> float:
        if len(data) < 48:
            raise TimeSyncError("Некорректный ответ от NTP сервера")

        # Формат: смещение времени отправки сервера - поле "Transmit Timestamp" (байты 40-47)
        # Timestamp в формате 64-бит: 32 бита - секунды, 32 бита - доли секунды
        transmit_timestamp = data[40:48]
        seconds, fraction = struct.unpack('!II', transmit_timestamp)
        timestamp = seconds + float(fraction) / 2**32

        # Переводим в UNIX-время
        unix_time = timestamp - self.NTP_TIMESTAMP_DELTA
        return unix_time

    def get_time(self) -> float:
        """
        Отправляет запрос серверу и получает время, учитывая RTT.
        Возвращает откорректированное время UNIX.
        """
        packet = self._build_request_packet()

        t1 = time.time()
        self.sock.sendto(packet, (self.server_ip, self.server_port))

        try:
            data, _ = self.sock.recvfrom(512)
        except socket.timeout:
            raise TimeSyncError("Таймаут при получении ответа от NTP сервера")
        t4 = time.time()

        t2 = self._parse_response(data)

        # Расчёт задержки и смещения по алгоритму NTP:
        # delay = (t4 - t1) - (t2 - t3), t3 приблизительно равно t2 в простом клиенте
        # offset = ((t2 - t1) + (t3 - t4)) / 2, упрощаем с t3 ≈ t2
        delay = (t4 - t1)
        offset = t2 - ((t1 + t4) / 2)

        corrected_time = time.time() + offset
        return corrected_time


class TimeSyncServer:
    """
    Простой UDP-сервер для обработки NTP-подобных запросов.
    Возвращает серверное время в формате NTP.
    """

    NTP_TIMESTAMP_DELTA = 2208988800

    def __init__(self, listen_ip: str = "0.0.0.0", listen_port: int = 123):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.listen_ip, self.listen_port))
        self.running = False

    def _build_response_packet(self, recv_packet: bytes) -> bytes:
        # Формируем ответ с текущим временем сервера в поле Transmit Timestamp
        # В простом варианте копируем часть запроса и вставляем время
        packet = bytearray(48)
        packet[0] = 0x1c  # LI=0 VN=3 Mode=4 (server)

        # Копируем в ответ часть запроса для соответствия полям (reference, originate timestamps)
        packet[24:32] = recv_packet[40:48]  # Originate Timestamp = Transmit Timestamp из запроса

        current_time = time.time() + self.NTP_TIMESTAMP_DELTA
        seconds = int(current_time)
        fraction = int((current_time - seconds) * 2**32)

        # Transmit Timestamp (байты 40-47)
        struct.pack_into('!II', packet, 40, seconds, fraction)

        return bytes(packet)

    def start(self):
        self.running = True
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                if data and len(data) >= 48:
                    response = self._build_response_packet(data)
                    self.sock.sendto(response, addr)
            except Exception:
                continue

    def stop(self):
        self.running = False
        self.sock.close()


# Дополнительно можно сделать синхронизацию с поправкой на локальные часы и логирование для аудита.
