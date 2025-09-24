# phantommesh-core/firewall_layer/pattern_blocker.py

import re
import logging
from typing import List, Dict, Optional, Callable
from ipaddress import ip_address

logger = logging.getLogger("pattern_blocker")
logger.setLevel(logging.DEBUG)

class SignatureRule:
    def __init__(self, name: str, pattern: str, description: str = "", critical: bool = False):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.description = description
        self.critical = critical

    def match(self, data: bytes) -> bool:
        try:
            return bool(self.pattern.search(data.decode(errors="ignore")))
        except Exception:
            return False

class IPBlockRule:
    def __init__(self, blocked_ip: str, reason: str = ""):
        self.ip = ip_address(blocked_ip)
        self.reason = reason

    def match(self, ip: str) -> bool:
        try:
            return ip_address(ip) == self.ip
        except Exception:
            return False

class PatternBlocker:
    def __init__(self):
        self.signature_rules: List[SignatureRule] = []
        self.blocked_ips: List[IPBlockRule] = []
        self.block_callbacks: List[Callable[[str, str], None]] = []

    def load_builtin_signatures(self):
        self.signature_rules.extend([
            SignatureRule("DPI_HTTP_TUNNEL", r"^CONNECT [^\s]+:443 HTTP/1.1", "HTTP tunnel over CONNECT", True),
            SignatureRule("TLS_FINGERPRINT_CISCO", r"^160301", "Known Cisco DPI TLS fingerprint"),
            SignatureRule("TOR_TLS_HEADER", r"\x16\x03\x01.{2}\x01\x00", "Tor TLS client hello", True),
            SignatureRule("OBFS4_HANDSHAKE", r"obfs4", "Plain-text obfs4 handshake leakage"),
            SignatureRule("FAKE_DNS_PAYLOAD", r"www\.thishostdoesnotexist", "Fake DNS used by DPI evasion testing")
        ])
        logger.info(f"Загружено {len(self.signature_rules)} сигнатур DPI")

    def load_blocked_ips(self, ip_list: List[Tuple[str, str]]):
        for ip, reason in ip_list:
            self.blocked_ips.append(IPBlockRule(ip, reason))
        logger.info(f"Загружено {len(self.blocked_ips)} IP-блоков")

    def register_callback(self, func: Callable[[str, str], None]) -> None:
        self.block_callbacks.append(func)

    def inspect_packet(self, ip_src: str, ip_dst: str, payload: bytes) -> Optional[str]:
        # Check IP first
        for rule in self.blocked_ips:
            if rule.match(ip_src) or rule.match(ip_dst):
                logger.warning(f"[BLOCKED IP] {ip_src} ↔ {ip_dst} ({rule.reason})")
                self._notify(ip_src, f"IP block: {rule.reason}")
                return f"ip:{rule.reason}"

        # Check signatures
        for rule in self.signature_rules:
            if rule.match(payload):
                logger.warning(f"[BLOCKED PATTERN] {rule.name}: {rule.description}")
                self._notify(ip_src, f"pattern:{rule.name}")
                return f"pattern:{rule.name}"

        return None

    def _notify(self, source_ip: str, reason: str):
        for cb in self.block_callbacks:
            cb(source_ip, reason)

    def reload_ruleset(self, rules: List[Dict]):
        self.signature_rules.clear()
        for r in rules:
            self.signature_rules.append(SignatureRule(
                name=r.get("name", "unnamed"),
                pattern=r["pattern"],
                description=r.get("description", ""),
                critical=r.get("critical", False)
            ))
        logger.info(f"Правила перезагружены: {len(self.signature_rules)} сигнатур")

    def export_active_rules(self) -> List[Dict]:
        return [{
            "name": rule.name,
            "pattern": rule.pattern.pattern,
            "description": rule.description,
            "critical": rule.critical
        } for rule in self.signature_rules]

    def clear(self):
        self.signature_rules.clear()
        self.blocked_ips.clear()
        self.block_callbacks.clear()
        logger.info("Все правила и блокировки очищены.")
