# chronowatch-core/chronowatch/timebase/ntp_client.py
# -*- coding: utf-8 -*-
"""
Асинхронный NTP/SNTP-клиент промышленного уровня для измерения смещения локальных часов.

Особенности:
- RFC 5905 совместимая клиентская выборка: NTPv3/v4 (SNTP mode 3 -> mode 4).
- IPv4/IPv6, UDP/123, конкурентные запросы к списку/пулу серверов.
- Таймауты, ретраи с экспоненциальной задержкой и джиттером.
- Точная отметка времени (time.time_ns), расчёт offset/delay, фильтрация невалидных ответов.
- Выбор «лучшего» ответа на основе stratums/delay/dispersion.
- Без внешних зависимостей, только стандартная библиотека Python 3.10+.
- Не изменяет системные часы; только измеряет поправку (offset) и даёт утилиты "корректированного" времени.

Пример:
    import asyncio
    from chronowatch.timebase.ntp_client import NTPClient

    async def main():
        client = NTPClient(
            servers=["time.google.com", "time.cloudflare.com", "pool.ntp.org"],
            timeout=1.0, retries=2, parallel_queries=4, log_level="INFO"
        )
        result = await client.synchronize()
        print(result)  # содержит offset_s, delay_s, server, stratum, и т.д.

    if __name__ == "__main__":
        asyncio.run(main())
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

# --------------------------- Константы и утилиты --------------------------- #

NTP_PORT = 123
NTP_UNIX_EPOCH_DELTA = 2208988800  # секунд от 1900-01-01 до 1970-01-01
NTP_PACKET_SIZE = 48

# Поля заголовка: LI(2) | VN(3) | Mode(3)
LI_NO_WARNING = 0
LI_ALARM = 3  # 3 == 11b: несинхронизирован, ответы неприменимы

MODE_CLIENT = 3
MODE_SERVER = 4
NTP_VERSION = 4

# Пороговые значения здравого смысла (анти-шум)
MAX_REASONABLE_DELAY_S = 5.0        # сетевой RTT > 5s считаем плохим
MAX_REASONABLE_OFFSET_S = 10.0      # смещение >10s — подозрительно для SNTP-клиента
MAX_STRATUM = 15                    # 0 и 16+ — недействительны (0 == kiss-o'-death)


def _now_unix_s() -> float:
    # высокоточное wall-clock время
    return time.time_ns() / 1_000_000_000.0


def _to_ntp_timestamp(t_unix: float) -> Tuple[int, int]:
    """
    Перевести unix time (секунды с плавующей точкой) в (секунды, фракции) NTP.
    """
    t = t_unix + NTP_UNIX_EPOCH_DELTA
    sec = int(t)
    frac = int((t - sec) * (1 << 32)) & 0xFFFFFFFF
    return sec & 0xFFFFFFFF, frac


def _from_ntp_timestamp(sec: int, frac: int) -> float:
    """
    Перевести NTP (секунды, фракции) в unix time (float seconds).
    """
    return (sec - NTP_UNIX_EPOCH_DELTA) + (frac / (1 << 32))


def _fixed_16_16_to_float(value: int) -> float:
    """
    Преобразовать 32-битное знаковое число с форматом 16.16 в float.
    """
    if value & 0x80000000:
        value = -((value ^ 0xFFFFFFFF) + 1) & 0xFFFFFFFF
        return -((value >> 16) + (value & 0xFFFF) / 65536.0)
    return (value >> 16) + (value & 0xFFFF) / 65536.0


# --------------------------- Структуры данных --------------------------- #

@dataclass(frozen=True)
class NTPServerAddress:
    host: str
    ip: str
    port: int = NTP_PORT
    family: int = socket.AF_INET


@dataclass(frozen=True)
class NTPResponse:
    server: NTPServerAddress
    leap: int
    version: int
    mode: int
    stratum: int
    poll: int
    precision_exp2: int
    root_delay_s: float
    root_dispersion_s: float
    reference_id: int
    ref_time_unix_s: float
    t1_unix_s: float
    t2_unix_s: float
    t3_unix_s: float
    t4_unix_s: float
    offset_s: float
    delay_s: float

    @property
    def precision_s(self) -> float:
        # precision хранится как степень двойки, отрицательное значение — субсекунды
        return 2.0 ** self.precision_exp2

    @property
    def is_valid(self) -> bool:
        if self.leap == LI_ALARM:
            return False
        if self.mode != MODE_SERVER:
            return False
        if self.stratum == 0 or self.stratum > MAX_STRATUM:
            return False
        if self.delay_s < 0 or self.delay_s > MAX_REASONABLE_DELAY_S:
            return False
        if abs(self.offset_s) > MAX_REASONABLE_OFFSET_S:
            # часто свидетельствует о неверно настроеном локальном часу либо сетевых аномалиях
            return False
        return True

    @property
    def quality_cost(self) -> float:
        """
        Эвристическая «стоимость» ответа: меньше — лучше.
        Учитывает stratum, сетевую задержку и root dispersion.
        """
        s = max(1, self.stratum)
        return (s * 0.5) + (self.delay_s * 1.0) + (self.root_dispersion_s * 0.25)


@dataclass(frozen=True)
class NTPResult:
    """
    Итог синхронизации: выбранный лучший ответ и срез по всем ответам.
    """
    best: Optional[NTPResponse]
    responses: Tuple[NTPResponse, ...] = field(default_factory=tuple)

    def corrected_time_unix_s(self, monotonic_time_unix_s: Optional[float] = None) -> Optional[float]:
        """
        Вернуть оценку «исправленного» текущего времени (unix seconds) на основе offset.
        Не меняет системных часов; полезно для прикладной коррекции.
        """
        if not self.best:
            return None
        base = _now_unix_s() if monotonic_time_unix_s is None else monotonic_time_unix_s
        return base + self.best.offset_s


# --------------------------- Исключения --------------------------- #

class NTPClientError(Exception):
    pass


class NTPTimeoutError(NTPClientError):
    pass


class NTPProtocolError(NTPClientError):
    pass


# --------------------------- Клиент --------------------------- #

class NTPClient:
    """
    Асинхронный NTP/SNTP-клиент.

    servers: список хостов (FQDN/IP). Поддерживаются pool.* домены — будут резолвиться в набор IP.
    timeout: таймаут одного запроса.
    retries: число повторов на один адрес.
    parallel_queries: максимальное число одновременных запросов.
    resolve_timeout: таймаут DNS-резолвинга.
    """
    def __init__(
        self,
        servers: Sequence[str],
        *,
        timeout: float = 1.0,
        retries: int = 2,
        parallel_queries: int = 4,
        resolve_timeout: float = 2.0,
        log_level: str = "WARNING",
    ) -> None:
        self.servers = list(servers)
        self.timeout = float(timeout)
        self.retries = int(retries)
        self.parallel_queries = max(1, int(parallel_queries))
        self.resolve_timeout = float(resolve_timeout)

        self._log = logging.getLogger("chronowatch.timebase.ntp")
        if not self._log.handlers:
            handler = logging.StreamHandler()
            fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
            handler.setFormatter(fmt)
            self._log.addHandler(handler)
        self._log.setLevel(getattr(logging, log_level.upper(), logging.WARNING))

    # -------------------- Публичный API -------------------- #

    async def synchronize(self) -> NTPResult:
        """
        Выполнить конкурентную синхронизацию со всеми доступными IP-адресами,
        вернуть лучший валидный ответ и полную выборку.
        """
        addrs = await self._resolve_all(self.servers)
        if not addrs:
            raise NTPClientError("No NTP addresses resolved")

        # Ограничаем уровень параллелизма (полезно против больших пулов)
        sem = asyncio.Semaphore(self.parallel_queries)
        tasks = []
        for addr in addrs:
            tasks.append(self._query_with_retries(addr, sem))

        results: List[Optional[NTPResponse]] = await asyncio.gather(*tasks, return_exceptions=False)
        responses = tuple(r for r in results if isinstance(r, NTPResponse) and r.is_valid)

        best: Optional[NTPResponse] = None
        if responses:
            best = min(responses, key=lambda r: (r.quality_cost, r.delay_s))

        return NTPResult(best=best, responses=responses)

    # -------------------- Внутренние утилиты -------------------- #

    async def _resolve_all(self, hosts: Sequence[str]) -> List[NTPServerAddress]:
        """
        Резолвинг всех хостов в набор (ip, family). IPv4/IPv6. Дедупликация.
        """
        addrs: List[NTPServerAddress] = []
        seen = set()

        async def resolve_host(host: str) -> None:
            try:
                res = await asyncio.wait_for(
                    asyncio.get_running_loop().getaddrinfo(
                        host, NTP_PORT, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP
                    ),
                    timeout=self.resolve_timeout,
                )
            except Exception as e:
                self._log.warning("DNS resolve failed for %s: %s", host, e)
                return
            for family, _type, _proto, _canon, sockaddr in res:
                ip, port, *rest = sockaddr
                key = (ip, port, family)
                if key in seen:
                    continue
                seen.add(key)
                addrs.append(NTPServerAddress(host=host, ip=ip, port=port, family=family))

        await asyncio.gather(*(resolve_host(h) for h in hosts))
        random.shuffle(addrs)  # равномерно распределим нагрузку по пулу
        return addrs

    async def _query_with_retries(self, addr: NTPServerAddress, sem: asyncio.Semaphore) -> Optional[NTPResponse]:
        delay_base = 0.2  # базовая задержка ретраев
        exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            # экспоненциальный бэк-офф с джиттером для последующих попыток
            if attempt > 0:
                backoff = delay_base * (2 ** (attempt - 1))
                await asyncio.sleep(backoff + random.uniform(0, backoff * 0.5))
            try:
                async with sem:
                    resp = await self._query_once(addr)
                    if resp.is_valid:
                        return resp
                    else:
                        self._log.debug("Invalid NTP response from %s: %s", addr.ip, resp)
                        exc = NTPProtocolError("Invalid NTP response")
            except (NTPTimeoutError, NTPProtocolError, OSError) as e:
                self._log.debug("Query failed [%s] for %s: %s", attempt, addr.ip, e)
                exc = e
                continue
        if exc:
            self._log.warning("All attempts failed for %s (%s)", addr.ip, exc)
        return None

    async def _query_once(self, addr: NTPServerAddress) -> NTPResponse:
        """
        Выполнить один запрос SNTP к конкретному адресу.
        """
        loop = asyncio.get_running_loop()

        # Создаём неблокирующий UDP сокет нужного семейства
        sock = socket.socket(addr.family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setblocking(False)
            # Ускоряем: "подключаем" UDP сокет к адресу — recv будет фильтровать пакеты по пиру
            sock.connect((addr.ip, addr.port))

            # Сформировать запрос
            li_vn_mode = (LI_NO_WARNING << 6) | (NTP_VERSION << 3) | MODE_CLIENT
            # Базовые поля:
            pkt = bytearray(NTP_PACKET_SIZE)
            struct.pack_into("!B B b b", pkt, 0, li_vn_mode, 0, 0, 0)  # LI/VN/Mode, stratum=0, poll=0, precision=0
            # Root Delay/Dispersion/RefID нулим (SNTP-клиент заполняет минимум)
            # Reference Timestamp: 8 байт нулей
            # Originate Timestamp: 8 байт нулей (сервер вернёт здесь T1)
            # Receive Timestamp: 8 байт нулей
            # Transmit Timestamp: заполним текущим временем
            t1 = _now_unix_s()
            sec, frac = _to_ntp_timestamp(t1)
            struct.pack_into("!II", pkt, 40, sec, frac)

            # Отправка и ожидание ответа
            try:
                await loop.sock_sendall(sock, pkt)
            except AttributeError:
                # Py<3.12 не имеет sock_sendall для UDP; fallback на send
                await loop.sock_sendto(sock, pkt, None)

            # Ждём ровно один пакет
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=self.timeout)
            except asyncio.TimeoutError:
                raise NTPTimeoutError(f"Timeout waiting NTP response from {addr.ip}")

            t4 = _now_unix_s()

            if len(data) < NTP_PACKET_SIZE:
                raise NTPProtocolError("Short NTP packet")

            # Парсинг заголовка
            (li_vn_mode_resp, stratum, poll, precision) = struct.unpack_from("!B B b b", data, 0)
            li = (li_vn_mode_resp >> 6) & 0x3
            vn = (li_vn_mode_resp >> 3) & 0x7
            mode = li_vn_mode_resp & 0x7

            # root delay/dispersion (16.16), refid (4 байта)
            (root_delay_raw, root_disp_raw, ref_id) = struct.unpack_from("!I I I", data, 4)
            root_delay = _fixed_16_16_to_float(root_delay_raw)
            root_disp = _fixed_16_16_to_float(root_disp_raw)

            # Timestamps (64-бит: 2x32)
            ref_sec, ref_frac = struct.unpack_from("!I I", data, 16)
            org_sec, org_frac = struct.unpack_from("!I I", data, 24)
            rec_sec, rec_frac = struct.unpack_from("!I I", data, 32)
            tx_sec, tx_frac = struct.unpack_from("!I I", data, 40)

            t2 = _from_ntp_timestamp(rec_sec, rec_frac)
            t3 = _from_ntp_timestamp(tx_sec, tx_frac)
            # серевер должен вернуть наш T1 в originate
            t1_echo = _from_ntp_timestamp(org_sec, org_frac)

            # Проверка отражения originate (допускаем небольшую ошибку квантования)
            if abs(t1_echo - t1) > 0.050:
                # некоторые сервера возвращают округление; если расхождение велико — отбрасываем
                raise NTPProtocolError("Originate timestamp mismatch")

            # Расчёт метрик
            delay = max(0.0, (t4 - t1) - (t3 - t2))
            offset = ((t2 - t1) + (t3 - t4)) / 2.0

            resp = NTPResponse(
                server=addr,
                leap=li,
                version=vn,
                mode=mode,
                stratum=int(stratum),
                poll=int(poll),
                precision_exp2=int(precision),
                root_delay_s=float(root_delay),
                root_dispersion_s=float(root_disp),
                reference_id=int(ref_id),
                ref_time_unix_s=_from_ntp_timestamp(ref_sec, ref_frac),
                t1_unix_s=t1,
                t2_unix_s=t2,
                t3_unix_s=t3,
                t4_unix_s=t4,
                offset_s=float(offset),
                delay_s=float(delay),
            )
            return resp
        finally:
            try:
                sock.close()
            except Exception:
                pass


# --------------------------- CLI/Пример --------------------------- #

async def _demo() -> None:
    servers = [
        os.getenv("NTP_SERVER_1", "time.google.com"),
        os.getenv("NTP_SERVER_2", "time.cloudflare.com"),
        os.getenv("NTP_SERVER_3", "pool.ntp.org"),
    ]
    client = NTPClient(servers, timeout=1.0, retries=2, parallel_queries=4, log_level=os.getenv("NTP_LOG", "INFO"))
    res = await client.synchronize()

    if not res.best:
        print("No valid NTP responses received")
        return

    b = res.best
    print("Best server:", f"{b.server.host} [{b.server.ip}]", "stratum:", b.stratum)
    print("Offset (s):", f"{b.offset_s:.6f}", "Delay (s):", f"{b.delay_s:.6f}", "RootDisp (s):", f"{b.root_dispersion_s:.6f}")
    print("LI:", b.leap, "Mode:", b.mode, "VN:", b.version, "Poll:", b.poll, "Precision(s):", b.precision_s)
    print("Corrected now (unix):", f"{res.corrected_time_unix_s():.6f}")


if __name__ == "__main__":
    # Простой демонстрационный запуск
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass
