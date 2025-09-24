# -*- coding: utf-8 -*-
"""
Интеграционные тесты IdP‑адаптера Zero‑Trust.

Что проверяем (если доступно):
1) OIDC discovery и кэширование JWKS.
2) Верификация RS256 подписи и базовых клаймов (iss, aud, sub, email, groups).
3) Контроль временных окон nbf/exp с учётом допустимого skew.
4) Защита от повторов по jti (replay detection).
5) Отзыв токенов (revocation).
6) Поток refresh (обновление id_token по refresh_token).

Зависимости:
- pytest (обязательно).
- cryptography (опционально; без неё криптографические сценарии помечаются как skip).

Ожидаемый интерфейс адаптера (если методы отсутствуют — тесты skip):
- zero_trust.idp.adapter.IdPAdapter(config: dict)
- .load_discovery() -> None
- .verify_id_token(token: str, *, nonce: str | None = None, max_skew_seconds: float | None = None) -> dict
- .refresh(refresh_token: str) -> dict  # возвращает {"id_token": "...", "access_token": "..."} (если реализовано)
- .revoke(jti: str) -> None  # поместить jti в локальный CRL/blacklist (если реализовано)
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import json
import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional

import pytest

# -----------------------------------------------------------------------------
# Опциональные импорты
# -----------------------------------------------------------------------------
try:
    # Наличие расширенного тайм-модуля переиспользуем для фиксации времени
    from zero_trust.utils.time import FrozenTime, format_rfc3339, now_utc_strict  # type: ignore
except Exception:
    FrozenTime = None  # type: ignore

    def format_rfc3339(dt: datetime, *, timespec: str = "seconds", use_z: bool = True) -> str:
        s = dt.astimezone(timezone.utc).isoformat(timespec=timespec)
        return s.replace("+00:00", "Z")

    def now_utc_strict() -> datetime:
        return datetime.now(timezone.utc)

# Криптография (опционально, тесты помечаются skip при отсутствии)
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

# IdP Adapter (если отсутствует — majority тестов будут skip)
_ADAPTER_IMPORT_ERR: Optional[Exception] = None
IdPAdapter = None
try:
    from zero_trust.idp.adapter import IdPAdapter  # type: ignore
except Exception as _e:  # pragma: no cover
    _ADAPTER_IMPORT_ERR = _e
    IdPAdapter = None  # type: ignore


# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def free_tcp_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_jwt_rs256(
    claims: Dict[str, Any],
    kid: str,
    private_key,
) -> str:
    """
    Подписать JWT RS256 вручную (без внешних либ JWT).
    Требует cryptography.
    """
    if not HAVE_CRYPTO:
        pytest.skip("cryptography не установлена: пропускаем криптотесты")
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    h_b = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    p_b = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signing_input = b".".join([b64url(h_b).encode("ascii"), b64url(p_b).encode("ascii")])
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{signing_input.decode('ascii')}.{b64url(signature)}"


def rsa_keypair():
    if not HAVE_CRYPTO:
        pytest.skip("cryptography не установлена: пропускаем криптотесты")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub


def jwk_from_public(pub, kid: str) -> Dict[str, Any]:
    if not HAVE_CRYPTO:
        pytest.skip("cryptography не установлена: пропускаем криптотесты")
    numbers = pub.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": b64url(n),
        "e": b64url(e),
    }


# -----------------------------------------------------------------------------
# Мок‑OIDC сервер
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class MockState:
    issuer: str
    jwks: Dict[str, Any]
    last_refresh_req: Optional[Dict[str, Any]] = None
    id_token_factory: Optional[callable] = None


class _Handler(BaseHTTPRequestHandler):
    server_version = "MockOIDC/1.0"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/.well-known/openid-configuration":
            body = {
                "issuer": self.server.state.issuer,
                "jwks_uri": f"{self.server.state.issuer}/jwks.json",
                "token_endpoint": f"{self.server.state.issuer}/token",
                "id_token_signing_alg_values_supported": ["RS256"],
            }
            self._json(body)
            return
        if self.path == "/jwks.json":
            self._json(self.server.state.jwks)
            return
        self._not_found()

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/token":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b""
            try:
                data = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                data = {}
            self.server.state.last_refresh_req = data
            # Выпускаем новый id_token через фабрику
            id_token = self.server.state.id_token_factory() if self.server.state.id_token_factory else "dummy"
            resp = {"access_token": "access-xyz", "token_type": "Bearer", "expires_in": 3600, "id_token": id_token}
            self._json(resp)
            return
        self._not_found()

    def log_message(self, fmt, *args):  # тишина в тестах
        return

    # Helpers
    def _json(self, obj: Dict[str, Any], code: int = 200) -> None:
        body = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self) -> None:
        self._json({"error": "not_found", "path": self.path}, code=404)


class MockServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, state: MockState):
        super().__init__(server_address, RequestHandlerClass)
        self.state = state


@contextlib.contextmanager
def run_mock_oidc(state: MockState):
    port = free_tcp_port()
    host = "127.0.0.1"
    state.issuer = f"http://{host}:{port}"
    httpd = MockServer((host, port), _Handler, state)
    thread = threading.Thread(target=httpd.serve_forever, name="mock-oidc", daemon=True)
    thread.start()
    try:
        yield state.issuer
    finally:
        httpd.shutdown()
        thread.join(timeout=2.0)


# -----------------------------------------------------------------------------
# Фикстуры pytest
# -----------------------------------------------------------------------------
@pytest.fixture(scope="module")
def keys():
    """RSA ключи и JWKS (или skip, если нет cryptography)."""
    if not HAVE_CRYPTO:
        pytest.skip("cryptography не установлена: пропускаем криптотесты")
    priv, pub = rsa_keypair()
    kid = "kid-1"
    jwks = {"keys": [jwk_from_public(pub, kid)]}
    return {"priv": priv, "pub": pub, "kid": kid, "jwks": jwks}


@pytest.fixture(scope="module")
def issuer_and_state(keys):
    """Поднимаем мок‑OIDC сервер."""
    state = MockState(issuer="http://127.0.0.1", jwks=keys["jwks"])
    with run_mock_oidc(state) as iss:
        yield iss, state


@pytest.fixture()
def adapter(issuer_and_state):
    """Инстанцируем адаптер, если доступен; иначе skip с причиной."""
    if IdPAdapter is None:
        pytest.skip(f"IdPAdapter недоступен: {_ADAPTER_IMPORT_ERR}")
    issuer, _ = issuer_and_state
    cfg = {
        "issuer": issuer,
        "client_id": "client-123",
        "jwks_cache_ttl": 5.0,
        "http_timeout": 2.0,
        "replay_cache_ttl": 60.0,
        "allowed_clock_skew_seconds": 10.0,
    }
    return IdPAdapter(cfg)  # type: ignore


# -----------------------------------------------------------------------------
# Тесты
# -----------------------------------------------------------------------------
@pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography не установлена")
def test_discovery_and_jwks_caching(adapter, issuer_and_state, keys):
    issuer, state = issuer_and_state
    # 1) discovery загрузка
    if not hasattr(adapter, "load_discovery"):
        pytest.skip("Метод load_discovery не реализован в адаптере")
    adapter.load_discovery()
    # 2) базовая верификация текущего JWKS
    now = now_utc_strict()
    claims = {
        "iss": issuer,
        "aud": "client-123",
        "sub": "user-42",
        "email": "user@example.org",
        "groups": ["dev", "sec"],
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 5,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "jti-1",
    }
    tok = make_jwt_rs256(claims, keys["kid"], keys["priv"])
    if not hasattr(adapter, "verify_id_token"):
        pytest.skip("Метод verify_id_token не реализован в адаптере")
    principal = adapter.verify_id_token(tok)
    assert principal and principal.get("sub") == "user-42"
    assert principal.get("email") == "user@example.org"
    assert set(principal.get("groups", [])) >= {"dev", "sec"}

    # 3) Меняем JWKS на сервере (эмулируем ротацию) и проверяем, что кэш удерживает старый ключ до TTL
    if hasattr(adapter, "_jwks_cache"):  # не обязательно, но полезно
        state.jwks = {"keys": []}  # сервер отдал бы пустой список, но кэш ещё валиден
        principal2 = adapter.verify_id_token(tok)
        assert principal2.get("sub") == "user-42"


@pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography не установлена")
def test_signature_and_claims(adapter, issuer_and_state, keys):
    issuer, _ = issuer_and_state
    now = now_utc_strict()
    good = {
        "iss": issuer,
        "aud": "client-123",
        "sub": "alice",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=1)).timestamp()),
        "jti": "unique-jti-1",
    }
    token = make_jwt_rs256(good, keys["kid"], keys["priv"])
    principal = adapter.verify_id_token(token, max_skew_seconds=10.0)
    assert principal["sub"] == "alice"

    # Подмена полезной нагрузки должна провалить подпись
    parts = token.split(".")
    tampered_payload = json.dumps({**good, "sub": "mallory"}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    bad_token = f"{parts[0]}.{b64url(tampered_payload)}.{parts[2]}"
    with pytest.raises(Exception):
        adapter.verify_id_token(bad_token, max_skew_seconds=10.0)


@pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography не установлена")
def test_clock_skew_enforced(adapter, issuer_and_state, keys):
    issuer, _ = issuer_and_state
    now = now_utc_strict()
    # nbf в будущем, но в пределах допустимого skew — должен пройти
    claims_ok = {
        "iss": issuer,
        "aud": "client-123",
        "sub": "bob",
        "iat": int(now.timestamp()),
        "nbf": int((now + timedelta(seconds=5)).timestamp()),
        "exp": int((now + timedelta(minutes=2)).timestamp()),
        "jti": "skew-ok",
    }
    t_ok = make_jwt_rs256(claims_ok, keys["kid"], keys["priv"])
    principal = adapter.verify_id_token(t_ok, max_skew_seconds=10.0)
    assert principal["sub"] == "bob"

    # nbf слишком далеко в будущем — должен упасть
    claims_bad = {
        **claims_ok,
        "sub": "charlie",
        "nbf": int((now + timedelta(seconds=60)).timestamp()),
        "jti": "skew-bad",
    }
    t_bad = make_jwt_rs256(claims_bad, keys["kid"], keys["priv"])
    with pytest.raises(Exception):
        adapter.verify_id_token(t_bad, max_skew_seconds=10.0)


@pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography не установлена")
def test_replay_detection_and_revocation(adapter, issuer_and_state, keys):
    issuer, _ = issuer_and_state
    now = now_utc_strict()
    claims = {
        "iss": issuer,
        "aud": "client-123",
        "sub": "dora",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "replay-jti",
    }
    token = make_jwt_rs256(claims, keys["kid"], keys["priv"])
    principal = adapter.verify_id_token(token, max_skew_seconds=10.0)
    assert principal["sub"] == "dora"

    # Повторное предъявление того же jti — должно быть отклонено, если реализован cache
    with pytest.raises(Exception):
        adapter.verify_id_token(token, max_skew_seconds=10.0)

    # Ревокация (если метод есть)
    if hasattr(adapter, "revoke"):
        adapter.revoke("replay-jti")
        with pytest.raises(Exception):
            adapter.verify_id_token(token, max_skew_seconds=10.0)
    else:
        pytest.xfail("Метод revoke не реализован в адаптере")


@pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography не установлена")
def test_refresh_flow(adapter, issuer_and_state, keys):
    issuer, state = issuer_and_state
    if not hasattr(adapter, "refresh"):
        pytest.xfail("Метод refresh не реализован в адаптере")

    now = now_utc_strict()
    def factory():
        claims = {
            "iss": issuer,
            "aud": "client-123",
            "sub": "refreshed-user",
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()) - 1,
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jti": f"jti-refresh-{int(time.time()*1000)}",
        }
        return make_jwt_rs256(claims, keys["kid"], keys["priv"])

    state.id_token_factory = factory
    resp = adapter.refresh("refresh-token-abc")
    assert "id_token" in resp and "access_token" in resp

    principal = adapter.verify_id_token(resp["id_token"])
    assert principal["sub"] == "refreshed-user"
    # проверим, что мок‑сервер получил запрос
    assert state.last_refresh_req is not None
