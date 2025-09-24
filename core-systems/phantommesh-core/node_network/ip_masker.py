# phantommesh-core/node_network/ip_masker.py

import asyncio
import random
import socket
import ssl
import time
import logging
import base64
import json
from typing import Optional, Tuple, Dict, List

import aiohttp

logger = logging.getLogger("ip_masker")
logger.setLevel(logging.DEBUG)

DOH_SERVERS = [
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
]

DOT_SERVERS = [
    ("1.1.1.1", 853),
    ("8.8.8.8", 853),
]

FAKE_IP_POOL = [
    "203.0.113.15", "198.51.100.24", "192.0.2.33", "172.31.255.1", "10.255.255.254"
]

class IPMasker:
    def __init__(self):
        self.doh_index = 0
        self.fake_ip_map: Dict[str, str] = {}
        self.cache: Dict[str, Tuple[str, float]] = {}

    def _generate_masked_ip(self, hostname: str) -> str:
        if hostname not in self.fake_ip_map:
            fake_ip = random.choice(FAKE_IP_POOL)
            self.fake_ip_map[hostname] = fake_ip
            logger.debug(f"Маскируем {hostname} → {fake_ip}")
        return self.fake_ip_map[hostname]

    def _cache_ip(self, hostname: str, ip: str, ttl: int = 300):
        self.cache[hostname] = (ip, time.time() + ttl)

    def _get_cached_ip(self, hostname: str) -> Optional[str]:
        if hostname in self.cache:
            ip, expiry = self.cache[hostname]
            if time.time() < expiry:
                return ip
            del self.cache[hostname]
        return None

    async def resolve_ip(self, hostname: str) -> Optional[str]:
        cached = self._get_cached_ip(hostname)
        if cached:
            return cached

        ip = await self._resolve_doh(hostname)
        if not ip:
            ip = await self._resolve_dot(hostname)

        if ip:
            self._cache_ip(hostname, ip)
            return ip
        return None

    async def _resolve_doh(self, hostname: str) -> Optional[str]:
        try:
            url = DOH_SERVERS[self.doh_index % len(DOH_SERVERS)]
            self.doh_index += 1

            query = {
                "name": hostname,
                "type": "A"
            }

            headers = {
                "Accept": "application/dns-json"
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=query, headers=headers, timeout=5) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        answers = result.get("Answer", [])
                        for answer in answers:
                            if answer.get("type") == 1:
                                return answer.get("data")
        except Exception as e:
            logger.warning(f"DOH fail: {e}")
        return None

    async def _resolve_dot(self, hostname: str) -> Optional[str]:
        try:
            context = ssl.create_default_context()
            for ip, port in DOT_SERVERS:
                reader, writer = await asyncio.open_connection(ip, port, ssl=context)
                query = self._build_dot_query(hostname)
                writer.write(query)
                await writer.drain()
                response = await reader.read(512)
                writer.close()
                await writer.wait_closed()

                ip = self._parse_dot_response(response)
                if ip:
                    return ip
        except Exception as e:
            logger.warning(f"DOT fail: {e}")
        return None

    def _build_dot_query(self, hostname: str) -> bytes:
        # Простой синтетический DNS-запрос (raw wireformat) — заменяется при внедрении полноценной библиотеки
        return b""

    def _parse_dot_response(self, data: bytes) -> Optional[str]:
        # Упрощённый парсер, нераспакованный для конфиденциальности — заменяется при продакшн-сборке
        return None

    def get_masked_ip(self, hostname: str) -> str:
        return self._generate_masked_ip(hostname)

    def export_map(self) -> Dict[str, str]:
        return dict(self.fake_ip_map)

    def clear(self) -> None:
        self.fake_ip_map.clear()
        self.cache.clear()
