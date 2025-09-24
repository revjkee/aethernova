import logging
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class HTTPThreatType:
    SQL_INJECTION = "SQL_INJECTION"
    XSS_ATTACK = "XSS_ATTACK"
    CSRF_TOKEN_MISSING = "CSRF_TOKEN_MISSING"
    UNTRUSTED_DOMAIN = "UNTRUSTED_DOMAIN"
    SSRF_ATTACK = "SSRF_ATTACK"
    HEADER_SPOOFING = "HEADER_SPOOFING"
    TOKEN_LEAKAGE = "TOKEN_LEAKAGE"
    UNKNOWN = "UNKNOWN"


class HTTPGuardResult:
    def __init__(self, allowed: bool, reason: Optional[str] = None, threat_type: Optional[str] = None):
        self.allowed = allowed
        self.reason = reason
        self.threat_type = threat_type

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "threat_type": self.threat_type
        }


class HTTPGuard:
    def __init__(self, trusted_domains: Optional[list[str]] = None):
        self.trusted_domains = trusted_domains or ["localhost", "teslaai.io"]

    def inspect_request(self, method: str, url: str, headers: Dict[str, str], body: str) -> HTTPGuardResult:
        if self._contains_sql_injection(body):
            return HTTPGuardResult(False, "Detected SQL injection", HTTPThreatType.SQL_INJECTION)

        if self._contains_xss(body):
            return HTTPGuardResult(False, "Detected XSS pattern", HTTPThreatType.XSS_ATTACK)

        if self._ssrf_detected(url):
            return HTTPGuardResult(False, "Possible SSRF detected", HTTPThreatType.SSRF_ATTACK)

        if self._token_leak_in_url(url):
            return HTTPGuardResult(False, "Token leakage in URL", HTTPThreatType.TOKEN_LEAKAGE)

        if not self._trusted_referer(headers):
            return HTTPGuardResult(False, "Untrusted Referer", HTTPThreatType.UNTRUSTED_DOMAIN)

        if self._header_spoofing(headers):
            return HTTPGuardResult(False, "Header spoofing detected", HTTPThreatType.HEADER_SPOOFING)

        if self._csrf_missing(method, headers):
            return HTTPGuardResult(False, "CSRF token missing", HTTPThreatType.CSRF_TOKEN_MISSING)

        return HTTPGuardResult(True)

    def _contains_sql_injection(self, payload: str) -> bool:
        sql_patterns = [
            r"(?i)(union\s+select)", r"(?i)(drop\s+table)", r"(?i)(--|\#)", r"(?i)(\bor\b.+\=)", r"(?i)(1\s*=\s*1)"
        ]
        return any(re.search(p, payload) for p in sql_patterns)

    def _contains_xss(self, payload: str) -> bool:
        xss_patterns = [
            r"(?i)<script.*?>.*?</script>", r"(?i)on\w+=['\"].*?['\"]", r"(?i)javascript:"
        ]
        return any(re.search(p, payload) for p in xss_patterns)

    def _ssrf_detected(self, url: str) -> bool:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return any(hostname.startswith(p) for p in ["127.", "169.254", "localhost", "0.0.0.0"])

    def _token_leak_in_url(self, url: str) -> bool:
        return bool(re.search(r"(access_token|api_key|secret)=\w+", url, re.IGNORECASE))

    def _trusted_referer(self, headers: Dict[str, str]) -> bool:
        referer = headers.get("Referer", "")
        return any(domain in referer for domain in self.trusted_domains)

    def _header_spoofing(self, headers: Dict[str, str]) -> bool:
        ip_headers = ["X-Forwarded-For", "X-Real-IP", "Client-IP"]
        values = [headers.get(h, "") for h in ip_headers]
        suspicious = [v for v in values if v and not self._is_valid_ip(v)]
        return bool(suspicious)

    def _is_valid_ip(self, ip: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))

    def _csrf_missing(self, method: str, headers: Dict[str, str]) -> bool:
        if method.upper() not in {"POST", "PUT", "DELETE"}:
            return False
        return "X-CSRF-Token" not in headers


# Экспорт
__all__ = ["HTTPGuard", "HTTPGuardResult", "HTTPThreatType"]
