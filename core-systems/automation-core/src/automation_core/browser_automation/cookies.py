# -*- coding: utf-8 -*-
"""
Cookie utilities for browser automation (Playwright/Selenium interop).

Design goals:
- Standards-aligned cookie model (RFC 6265) with conservative validation.
- SameSite handling with enforcement: SameSite=None requires Secure (MDN).
- Import/export helpers for Playwright and Selenium.
- Applicability checks (domain, path, secure) and expiry pruning.
- Durable NDJSON storage with HMAC-SHA256 integrity and cross-platform file locks.
- No third-party runtime dependencies.

References:
- RFC 6265: HTTP State Management Mechanism (cookie semantics).  # see docs in project README
- MDN Set-Cookie / SameSite: “SameSite=None” requires Secure.
- Playwright BrowserContext.addCookies / cookies() shape.
- Selenium WebDriver cookies: required/optional keys.

NOTE:
Public Suffix List handling is out of scope; we implement host-only vs domain-cookie
matching per RFC and assume caller provides safe domains.

Author: automation-core
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import io
import json
import os
import re
import sys
import time
import typing
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

# ------------------------------ Types & model ------------------------------- #

SameSite = typing.Literal["Lax", "Strict", "None"]

_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")  # RFC6265 token-like
_PATH_SANITY_RE = re.compile(r"^/")  # must start with "/"

@dataclass(frozen=True)
class Cookie:
    """
    Minimal yet robust cookie model aligned with RFC 6265 and common automation tools.

    name/value: opaque strings (value may be empty).
    domain: if startswith '.', treated as a domain cookie (matches subdomains), else host-only.
    path: normalized path prefix, defaults to "/".
    expires: UNIX seconds (int) or None for session cookie.
    http_only / secure: booleans.
    same_site: "Lax" | "Strict" | "None" | None (unspecified).

    Invariants:
    - name must match token-like pattern per RFC 6265.
    - path starts with "/" (default "/").
    - If same_site == "None", secure must be True (browser enforcement).
    """
    name: str
    value: str
    domain: str
    path: str = "/"
    expires: Optional[int] = None
    http_only: bool = False
    secure: bool = False
    same_site: Optional[SameSite] = None
    creation_utc: Optional[int] = None
    last_access_utc: Optional[int] = None

    def __post_init__(self) -> None:
        # name validation
        if not self.name or not _COOKIE_NAME_RE.match(self.name):
            raise ValueError(f"Invalid cookie name: {self.name!r}")
        # path normalization
        if not self.path or not _PATH_SANITY_RE.match(self.path):
            object.__setattr__(self, "path", "/")
        # domain normalization (lowercase)
        object.__setattr__(self, "domain", self.domain.lstrip(".").lower() if self.domain else "")
        # SameSite=None requires Secure
        if self.same_site == "None" and not self.secure:
            # hard enforcement to prevent invalid state in automation
            raise ValueError("SameSite=None requires Secure=True")

        # expires normalization to int
        if self.expires is not None:
            try:
                object.__setattr__(self, "expires", int(self.expires))
            except Exception as e:
                raise ValueError("expires must be UNIX seconds (int)") from e

        now = int(time.time())
        if self.creation_utc is None:
            object.__setattr__(self, "creation_utc", now)
        if self.last_access_utc is None:
            object.__setattr__(self, "last_access_utc", now)

    # ----------------------- Applicability & helpers ----------------------- #

    def is_expired(self, now: Optional[int] = None) -> bool:
        if self.expires is None:
            return False
        now = int(time.time()) if now is None else int(now)
        return self.expires <= now

    def matches_request(self, url: str, is_secure_transport: Optional[bool] = None) -> bool:
        """
        Returns True if cookie is applicable to the given request URL per basic RFC 6265 rules.

        - Domain-match: host-only cookie matches only exact host.
                        domain cookie (Set-Cookie with Domain) matches the suffix boundary.
        - Path-match: request-path must start with cookie.path prefix.
        - Secure: if cookie.secure True and request is not https, not applicable.

        This is a conservative subset (no PSL, no schemeful SameSite).
        """
        try:
            u = urlparse(url)
        except Exception:
            return False
        if u.scheme not in ("http", "https"):
            return False

        host = (u.hostname or "").lower()
        if not host:
            return False

        # secure transport detection if not provided
        if is_secure_transport is None:
            is_secure_transport = (u.scheme == "https")

        # Secure flag
        if self.secure and not is_secure_transport:
            return False

        # Domain-match
        if not self._domain_match(host):
            return False

        # Path-match
        req_path = u.path or "/"
        if not req_path.startswith(self.path):
            return False

        # Expiry
        if self.is_expired():
            return False

        return True

    def _domain_match(self, host: str) -> bool:
        """
        Host-only: exact match; Domain attribute: suffix-match on label boundary.
        """
        cdomain = self.domain
        if not cdomain:
            return False
        # If originally set as host-only, cdomain equals host; our normalization loses the leading dot.
        if host == cdomain:
            return True
        # Domain cookie: allow subdomains "x.cdomain"
        if host.endswith("." + cdomain):
            return True
        return False

    # ------------------------- Interop: Playwright ------------------------- #

    def to_playwright(self) -> Dict[str, Any]:
        """
        Convert to Playwright cookie object fields:
        { name, value, domain, path, expires, httpOnly, secure, sameSite }
        """
        obj: Dict[str, Any] = {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "path": self.path,
            "httpOnly": self.http_only,
            "secure": self.secure,
        }
        if self.expires is not None:
            obj["expires"] = self.expires
        if self.same_site is not None:
            obj["sameSite"] = self.same_site
        return obj

    @staticmethod
    def from_playwright(obj: Dict[str, Any]) -> "Cookie":
        """
        Build from Playwright cookies() / addCookies() shape.
        """
        return Cookie(
            name=str(obj["name"]),
            value=str(obj.get("value", "")),
            domain=str(obj.get("domain", "")),
            path=str(obj.get("path", "/") or "/"),
            expires=int(obj["expires"]) if "expires" in obj and obj["expires"] is not None else None,
            http_only=bool(obj.get("httpOnly", False)),
            secure=bool(obj.get("secure", False)),
            same_site=(obj.get("sameSite") if obj.get("sameSite") in ("Lax", "Strict", "None") else None),  # type: ignore
        )

    # ------------------------- Interop: Selenium --------------------------- #

    def to_selenium(self) -> Dict[str, Any]:
        """
        Convert to Selenium cookie dict:
        required: name, value
        optional: domain, path, expiry, httpOnly, secure, sameSite
        """
        obj: Dict[str, Any] = {
            "name": self.name,
            "value": self.value,
        }
        if self.domain:
            obj["domain"] = self.domain
        if self.path:
            obj["path"] = self.path
        if self.expires is not None:
            obj["expiry"] = self.expires
        if self.http_only:
            obj["httpOnly"] = True
        if self.secure:
            obj["secure"] = True
        if self.same_site is not None:
            obj["sameSite"] = self.same_site
        return obj

    @staticmethod
    def from_selenium(obj: Dict[str, Any]) -> "Cookie":
        return Cookie(
            name=str(obj["name"]),
            value=str(obj.get("value", "")),
            domain=str(obj.get("domain", "")),
            path=str(obj.get("path", "/") or "/"),
            expires=int(obj["expiry"]) if "expiry" in obj and obj["expiry"] is not None else None,
            http_only=bool(obj.get("httpOnly", False)),
            secure=bool(obj.get("secure", False)),
            same_site=(obj.get("sameSite") if obj.get("sameSite") in ("Lax", "Strict", "None") else None),  # type: ignore
        )

# ------------------------------- Cookie Jar --------------------------------- #

class CookieJar:
    """
    Thread-safe, integrity-protected cookie store.

    Storage format:
    - NDJSON file: one JSON object per line {"type":"cookie","data":{...}}
    - Sidecar HMAC-SHA256 file <path>.hmac covering bytes of NDJSON file.

    Locking:
    - Cross-platform advisory file lock (best-effort). Prevents concurrent writers.
    """

    VERSION = 1

    def __init__(self) -> None:
        self._cookies: Dict[Tuple[str, str, str], Cookie] = {}
        self._lock = RLock()

    # ------------- core ops ------------ #

    def _key(self, c: Cookie) -> Tuple[str, str, str]:
        # unique by (domain, path, name)
        return (c.domain, c.path, c.name)

    def add(self, c: Cookie) -> None:
        with self._lock:
            self._cookies[self._key(c)] = c

    def remove(self, name: str, domain: str, path: str = "/") -> bool:
        with self._lock:
            return self._cookies.pop((domain.lower().lstrip("."), path or "/", name), None) is not None

    def get(self, name: str, domain: str, path: str = "/") -> Optional[Cookie]:
        with self._lock:
            return self._cookies.get((domain.lower().lstrip("."), path or "/", name))

    def clear(self) -> None:
        with self._lock:
            self._cookies.clear()

    def all(self) -> List[Cookie]:
        with self._lock:
            return list(self._cookies.values())

    def prune_expired(self, now: Optional[int] = None) -> int:
        with self._lock:
            now = int(time.time()) if now is None else int(now)
            keys = [k for k, v in self._cookies.items() if v.expires is not None and v.expires <= now]
            for k in keys:
                self._cookies.pop(k, None)
            return len(keys)

    # -------- applicability / selection -------- #

    def cookies_for_url(self, url: str) -> List[Cookie]:
        with self._lock:
            return [c for c in self._cookies.values() if c.matches_request(url)]

    # -------------------- interop -------------------- #

    def import_playwright(self, cookies: Sequence[Dict[str, Any]]) -> int:
        n = 0
        for obj in cookies:
            self.add(Cookie.from_playwright(obj))
            n += 1
        return n

    def export_playwright(self) -> List[Dict[str, Any]]:
        return [c.to_playwright() for c in self.all()]

    def import_selenium(self, cookies: Sequence[Dict[str, Any]]) -> int:
        n = 0
        for obj in cookies:
            self.add(Cookie.from_selenium(obj))
            n += 1
        return n

    def export_selenium(self) -> List[Dict[str, Any]]:
        return [c.to_selenium() for c in self.all()]

    # ---------------- persistence (NDJSON + HMAC) ---------------- #

    def save(self, path: typing.Union[str, Path], *, hmac_key: Optional[bytes] = None) -> None:
        """
        Save jar as NDJSON; if hmac_key provided, write <path>.hmac with HMAC-SHA256.
        """
        path = Path(path)
        payload = io.StringIO()
        # header
        header = {"type": "header", "version": self.VERSION, "ts": int(time.time())}
        payload.write(json.dumps(header, ensure_ascii=False) + "\n")
        # cookies
        for c in self.all():
            payload.write(json.dumps({"type": "cookie", "data": dataclasses.asdict(c)}, ensure_ascii=False) + "\n")
        data = payload.getvalue().encode("utf-8")

        with _locked_file(path, "wb") as f:
            f.write(data)

        if hmac_key:
            mac = hmac.new(hmac_key, data, hashlib.sha256).digest()
            Path(str(path) + ".hmac").write_bytes(base64.b64encode(mac))

    @classmethod
    def load(cls, path: typing.Union[str, Path], *, hmac_key: Optional[bytes] = None, require_hmac: bool = False) -> "CookieJar":
        """
        Load jar from NDJSON; verify HMAC if provided or required.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(str(path))
        data = path.read_bytes()

        if hmac_key or require_hmac:
            sig_path = Path(str(path) + ".hmac")
            if not sig_path.exists():
                if require_hmac:
                    raise ValueError("HMAC required but .hmac file missing")
            else:
                mac = base64.b64decode(sig_path.read_bytes())
                calc = hmac.new(hmac_key or b"", data, hashlib.sha256).digest()
                if not hmac.compare_digest(mac, calc):
                    raise ValueError("HMAC verification failed")

        jar = cls()
        for line in data.splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("type") == "cookie":
                cdict = obj["data"]
                # Backward-safe: ignore unknown keys
                jar.add(Cookie(**{
                    "name": cdict["name"],
                    "value": cdict["value"],
                    "domain": cdict["domain"],
                    "path": cdict.get("path", "/") or "/",
                    "expires": cdict.get("expires"),
                    "http_only": cdict.get("http_only", False),
                    "secure": cdict.get("secure", False),
                    "same_site": cdict.get("same_site"),
                    "creation_utc": cdict.get("creation_utc"),
                    "last_access_utc": cdict.get("last_access_utc"),
                }))
        return jar


# --------------------- Cross-platform file locking -------------------------- #

class _FileLock:
    def __init__(self, fileobj):
        self.f = fileobj

    def __enter__(self):
        if os.name == "nt":
            import msvcrt  # type: ignore
            # Lock entire file (advisory for our usage)
            msvcrt.locking(self.f.fileno(), msvcrt.LK_LOCK, 0x7FFFFFFF)
        else:
            import fcntl  # type: ignore
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        return self.f

    def __exit__(self, exc_type, exc, tb):
        if os.name == "nt":
            import msvcrt  # type: ignore
            try:
                msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 0x7FFFFFFF)
            finally:
                self.f.close()
        else:
            import fcntl  # type: ignore
            try:
                fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            finally:
                self.f.close()


def _locked_file(path: Path, mode: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    f = open(path, mode)
    return _FileLock(f)

# ----------------------------- Convenience ---------------------------------- #

def jar_from_playwright_context(context: Any) -> CookieJar:
    """
    Extract cookies from a Playwright BrowserContext into a CookieJar.
    `context.cookies()` returns list of cookie dicts; see Playwright docs.
    """
    cookies = context.cookies()
    jar = CookieJar()
    jar.import_playwright(cookies)
    return jar


def apply_jar_to_playwright_context(jar: CookieJar, context: Any) -> None:
    """
    Add all cookies from CookieJar into Playwright BrowserContext.
    """
    context.addCookies(jar.export_playwright())


def jar_from_selenium_driver(driver: Any) -> CookieJar:
    """
    Extract cookies from Selenium WebDriver into a CookieJar.
    """
    cookies = driver.get_cookies()
    jar = CookieJar()
    jar.import_selenium(cookies)
    return jar


def apply_jar_to_selenium_driver(jar: CookieJar, driver: Any) -> None:
    """
    Add all cookies from CookieJar into Selenium WebDriver.
    """
    for c in jar.export_selenium():
        driver.add_cookie(c)


__all__ = [
    "Cookie",
    "CookieJar",
    "SameSite",
    "jar_from_playwright_context",
    "apply_jar_to_playwright_context",
    "jar_from_selenium_driver",
    "apply_jar_to_selenium_driver",
]
