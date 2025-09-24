"""
svid_manager.py — промышленный менеджер SPIFFE SVID для Python-сервисов.

Возможности:
- Получение и автоматическая ротация X.509 SVID (и, опционально, JWT-SVID).
- Два режима работы:
  1) FILE: чтение cert/key/bundle из файлов с безопасной перепроверкой и авто-ротацией.
  2) WORKLOAD_API: через py-spiffe (если установлен), либо аккуратная ошибка с подсказкой.
- Выдача готового ssl.SSLContext для mTLS-клиента/сервера с безопасными настройками.
- Ранний рефреш (до истечения), адаптивные интервалы опроса, экспоненциальный бэкофф с джиттером.
- Потокобезопасный доступ, асинхронная модель, подписчики на события ротации.
- Опциональная публикация актуальных PEM-файлов на диск (для sidecar/инструментов).

Зависимости:
- Базовые: стандартная библиотека Python 3.11+.
- Опционально: cryptography (для строгой валидации ключа/серта и чтения NotAfter).
- Опционально: py-spiffe (для режима WORKLOAD_API).
- Опционально: prometheus_client (метрики), но код работает и без него.

Пример использования:
    settings = SVIDManagerSettings(
        mode="FILE",
        file_cert_path=Path("/var/run/spire/svid.pem"),
        file_key_path=Path("/var/run/spire/svid.key"),
        file_bundle_path=Path("/var/run/spire/bundle.pem"),
        publish_dir=Path("/var/run/identity"),
        trust_check_strict=True,
    )
    mgr = SVIDManager(settings)
    await mgr.start()
    ssl_ctx = await mgr.get_ssl_context()  # готовый контекст для httpx/grpc
    # ...
    await mgr.stop()

Автор: Aethernova / security-core
Лицензия: Apache-2.0
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import random
import ssl
import stat
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Awaitable, Callable, Dict, Iterable, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Опциональные зависимости
try:  # cryptography — для разбора X.509 и проверки связки ключ/сертификат
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    _CRYPTO_AVAILABLE = True
except Exception:  # noqa: BLE001
    x509 = None  # type: ignore
    serialization = None  # type: ignore
    rsa = None  # type: ignore
    ec = None  # type: ignore
    _CRYPTO_AVAILABLE = False

try:  # py-spiffe — для Workload API
    # Импорт ленивый в провайдере; наличие флага достаточно
    import spiffe  # type: ignore
    _SPIFFE_AVAILABLE = True
except Exception:  # noqa: BLE001
    _SPIFFE_AVAILABLE = False

# Метрики (опционально)
try:
    from prometheus_client import Gauge, Counter  # type: ignore
    _METRICS = {
        "svid_not_after_timestamp": Gauge("svid_not_after_timestamp", "SVID NotAfter (unix ts)"),
        "svid_rotation_events_total": Counter("svid_rotation_events_total", "SVID rotation events"),
        "svid_load_failures_total": Counter("svid_load_failures_total", "SVID load failures"),
        "svid_jwt_issued_total": Counter("svid_jwt_issued_total", "JWT SVID issued"),
    }
except Exception:  # noqa: BLE001
    _METRICS = None


# =========================
# Исключения и типы
# =========================

class SVIDError(RuntimeError):
    """Общий класс ошибок менеджера SVID."""


@dataclass(frozen=True)
class X509Identity:
    cert_chain_pem: str
    private_key_pem: str
    trust_bundle_pem: Optional[str]
    spiffe_id: Optional[str]
    not_after: Optional[datetime]

    def is_valid(self) -> bool:
        return bool(self.cert_chain_pem and self.private_key_pem)


@dataclass(frozen=True)
class JwtIdentity:
    token: str
    audience: Tuple[str, ...]
    not_after: Optional[datetime]
    spiffe_id: Optional[str]


@dataclass
class SVIDManagerSettings:
    mode: str = "FILE"  # "FILE" | "WORKLOAD_API"
    trust_check_strict: bool = True

    # FILE mode paths
    file_cert_path: Optional[Path] = None
    file_key_path: Optional[Path] = None
    file_bundle_path: Optional[Path] = None

    # WORKLOAD API (через py-spiffe)
    spiffe_socket: Optional[str] = field(
        default_factory=lambda: os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    )
    trust_domain: Optional[str] = None  # например: "example.org"

    # Rotation thresholds
    min_refresh_interval: timedelta = field(default=timedelta(seconds=15))
    max_refresh_interval: timedelta = field(default=timedelta(minutes=10))
    refresh_skew: timedelta = field(default=timedelta(minutes=5))  # обновить за N до NotAfter
    hard_fail_after: timedelta = field(default=timedelta(minutes=2))  # после NotAfter+N — ошибка

    # SSL/TLS
    ssl_min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    ssl_ciphers: str = (
        "ECDHE+AESGCM:ECDHE+CHACHA20:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
    )
    verify_hostname: bool = False  # для SPIFFE обычно False; hostname проверяется верхним слоем

    # Publish to disk (опционально)
    publish_dir: Optional[Path] = None  # если задан — писать svid.pem/svid.key/bundle.pem (atomic)

    # JWT SVID
    default_audience: Tuple[str, ...] = field(default_factory=tuple)


RotationListener = Callable[[X509Identity], Awaitable[None]]


# =========================
# Провайдеры SVID
# =========================

class BaseSVIDProvider:
    """Интерфейс получения SVID и бандла."""

    async def fetch_x509(self) -> X509Identity:
        raise NotImplementedError

    async def fetch_jwt(self, audience: Iterable[str]) -> JwtIdentity:
        raise NotImplementedError


class FileSVIDProvider(BaseSVIDProvider):
    """Провайдер, читающий SVID/бандл из файловой системы."""

    def __init__(
        self,
        cert_path: Path,
        key_path: Path,
        bundle_path: Optional[Path],
        trust_strict: bool = True,
    ) -> None:
        self._cert_path = cert_path
        self._key_path = key_path
        self._bundle_path = bundle_path
        self._trust_strict = trust_strict

    @staticmethod
    def _read_file(p: Path) -> str:
        data = p.read_text(encoding="utf-8")
        st = p.stat()
        # Базовая проверка прав на ключ
        if p.suffix in (".key",) and (st.st_mode & stat.S_IROTH):
            logger.warning("Private key %s is world-readable; consider chmod 600", p)
        return data

    @staticmethod
    def _parse_not_after(cert_pem: str) -> Optional[datetime]:
        if not _CRYPTO_AVAILABLE:
            return None
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            return cert.not_valid_after.replace(tzinfo=timezone.utc)
        except Exception as e:  # noqa: BLE001
            logger.warning("Cannot parse certificate NotAfter: %s", e)
            return None

    @staticmethod
    def _extract_spiffe_id(cert_pem: str) -> Optional[str]:
        if not _CRYPTO_AVAILABLE:
            return None
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            for ext in cert.extensions:
                # URI SAN с urn:spiffe
                if isinstance(ext.value, x509.SubjectAlternativeName):
                    for gn in ext.value.get_values_for_type(x509.UniformResourceIdentifier):
                        if gn.startswith("spiffe://"):
                            return gn
            return None
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _validate_key_match(cert_pem: str, key_pem: str) -> None:
        if not _CRYPTO_AVAILABLE:
            return
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        pub = cert.public_key()
        key = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)
        try:
            if isinstance(pub, rsa.RSAPublicKey) and hasattr(key, "public_key"):
                if pub.public_numbers() != key.public_key().public_numbers():  # type: ignore[attr-defined]
                    raise SVIDError("Certificate public key does not match private key")
            elif isinstance(pub, ec.EllipticCurvePublicKey) and hasattr(key, "public_key"):
                if pub.public_numbers() != key.public_key().public_numbers():  # type: ignore[attr-defined]
                    raise SVIDError("Certificate public key does not match private key")
            else:
                # Иные ключи: пробуем подписать/верифицировать при необходимости
                pass
        except Exception as e:  # noqa: BLE001
            raise SVIDError(f"Private key mismatch: {e}") from e

    async def fetch_x509(self) -> X509Identity:
        cert_chain = self._read_file(self._cert_path)
        key_pem = self._read_file(self._key_path)
        bundle = self._read_file(self._bundle_path) if self._bundle_path else None

        # Валидация ключа и сроков
        self._validate_key_match(cert_chain, key_pem)
        not_after = self._parse_not_after(cert_chain.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----")
        spiffe_id = self._extract_spiffe_id(cert_chain)

        if self._trust_strict and not bundle:
            raise SVIDError("Trust bundle is required in strict mode")

        return X509Identity(
            cert_chain_pem=cert_chain,
            private_key_pem=key_pem,
            trust_bundle_pem=bundle,
            spiffe_id=spiffe_id,
            not_after=not_after,
        )

    async def fetch_jwt(self, audience: Iterable[str]) -> JwtIdentity:
        raise SVIDError("JWT SVID not supported in FILE mode")


class WorkloadApiSVIDProvider(BaseSVIDProvider):
    """
    Провайдер Workload API через py-spiffe.
    Требует переменной окружения SPIFFE_ENDPOINT_SOCKET или явного пути.
    """

    def __init__(self, socket_path: Optional[str], trust_domain: Optional[str]) -> None:
        if not _SPIFFE_AVAILABLE:
            raise SVIDError(
                "py-spiffe not installed. Install: pip install py-spiffe"
            )
        self._socket_path = socket_path or os.environ.get("SPIFFE_ENDPOINT_SOCKET")
        self._trust_domain = trust_domain

        # Импорты только при реальном использовании, чтобы не падать при проверках
        from spiffe.workloadapi.default_x509_source import (  # type: ignore
            DefaultX509Source,
        )
        from spiffe.workloadapi.default_jwt_source import (  # type: ignore
            DefaultJwtSource,
        )

        self._x509_source = DefaultX509Source(spiffe_socket_path=self._socket_path)  # type: ignore
        self._jwt_source = DefaultJwtSource(spiffe_socket_path=self._socket_path)  # type: ignore

    async def fetch_x509(self) -> X509Identity:
        # py-spiffe API — синхронный; оборачиваем в executor
        def _load() -> X509Identity:
            svid = self._x509_source.get_x509_svid()  # type: ignore[attr-defined]
            bundle = self._x509_source.get_x509_bundle_set()  # type: ignore[attr-defined]
            chain_pem = svid.cert_chain_as_pem().decode("utf-8")  # type: ignore[attr-defined]
            key_pem = svid.private_key_as_pem().decode("utf-8")  # type: ignore[attr-defined]
            # Собираем trust bundle по trust domain
            bundle_pem = None
            if self._trust_domain:
                td_bundle = bundle.get_x509_bundle_for_trust_domain(self._trust_domain)  # type: ignore[attr-defined]
                bundle_pem = td_bundle.pem().decode("utf-8")  # type: ignore[attr-defined]
            # Оценка NotAfter по первому сертификату цепочки
            not_after = None
            if _CRYPTO_AVAILABLE:
                try:
                    first_cert_pem = chain_pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----"
                    cert = x509.load_pem_x509_certificate(first_cert_pem.encode("utf-8"))
                    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                except Exception:  # noqa: BLE001
                    pass
            # SPIFFE ID
            spiffe_id = None
            try:
                spiffe_id = svid.spiffe_id().URI()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass
            return X509Identity(
                cert_chain_pem=chain_pem,
                private_key_pem=key_pem,
                trust_bundle_pem=bundle_pem,
                spiffe_id=spiffe_id,
                not_after=not_after,
            )

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _load)

    async def fetch_jwt(self, audience: Iterable[str]) -> JwtIdentity:
        def _load() -> JwtIdentity:
            token = self._jwt_source.fetch_jwt_svid(audience=list(audience))  # type: ignore[attr-defined]
            exp = None
            try:
                exp = datetime.fromtimestamp(token.expires_at(), tz=timezone.utc)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass
            sid = None
            try:
                sid = token.spiffe_id().URI()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass
            return JwtIdentity(token=token.token(), audience=tuple(audience), not_after=exp, spiffe_id=sid)  # type: ignore[attr-defined]

        loop = asyncio.get_running_loop()
        ji = await loop.run_in_executor(None, _load)
        if _METRICS:
            _METRICS["svid_jwt_issued_total"].inc()  # type: ignore[union-attr]
        return ji


# =========================
# Менеджер SVID
# =========================

class SVIDManager:
    """Асинхронный менеджер SVID: ротация, SSLContext, публикация, слушатели."""

    def __init__(self, settings: SVIDManagerSettings) -> None:
        self._settings = settings
        self._lock = asyncio.Lock()
        self._cur: Optional[X509Identity] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._listeners: Dict[str, RotationListener] = {}
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

        # Провайдер
        if settings.mode.upper() == "FILE":
            if not settings.file_cert_path or not settings.file_key_path:
                raise SVIDError("FILE mode requires file_cert_path and file_key_path")
            self._provider: BaseSVIDProvider = FileSVIDProvider(
                settings.file_cert_path,
                settings.file_key_path,
                settings.file_bundle_path,
                trust_strict=settings.trust_check_strict,
            )
        elif settings.mode.upper() == "WORKLOAD_API":
            self._provider = WorkloadApiSVIDProvider(
                settings.spiffe_socket, settings.trust_domain
            )
        else:
            raise SVIDError(f"Unknown SVID mode: {settings.mode}")

    # ---------- Публичный API ----------

    async def start(self) -> None:
        """Старт фоновой ротации."""
        async with self._lock:
            if self._task and not self._task.done():
                return
            await self._refresh_identity(initial=True)
            self._stop_event.clear()
            self._task = asyncio.create_task(self._rotation_loop(), name="svid-rotation")

    async def stop(self) -> None:
        """Остановка фоновой ротации."""
        self._stop_event.set()
        task = self._task
        if task:
            await task
        self._task = None

    async def get_ssl_context(self) -> ssl.SSLContext:
        """Получить актуальный SSLContext (создается/обновляется атомарно)."""
        async with self._lock:
            if self._ssl_context is None:
                raise SVIDError("SVID not initialized")
            return self._ssl_context

    async def get_x509_identity(self) -> X509Identity:
        async with self._lock:
            if not self._cur:
                raise SVIDError("SVID not initialized")
            return self._cur

    async def issue_jwt(self, audience: Optional[Iterable[str]] = None) -> JwtIdentity:
        """Запросить JWT‑SVID у провайдера (если поддерживает)."""
        aud = tuple(audience) if audience else self._settings.default_audience
        if not aud:
            raise SVIDError("Audience required for JWT SVID")
        ji = await self._provider.fetch_jwt(aud)
        return ji

    def add_rotation_listener(self, name: str, cb: RotationListener) -> None:
        """Подписка на события ротации (async callback)."""
        self._listeners[name] = cb

    def remove_rotation_listener(self, name: str) -> None:
        self._listeners.pop(name, None)

    # ---------- Внутренняя логика ----------

    async def _rotation_loop(self) -> None:
        backoff = 1.0
        while not self._stop_event.is_set():
            try:
                delay = await self._next_delay()
                await asyncio.wait_for(self._stop_event.wait(), timeout=delay)
                if self._stop_event.is_set():
                    break
                await self._refresh_identity()
                backoff = 1.0
            except asyncio.TimeoutError:
                # Обычный цикл ожидания — идем дальше
                continue
            except Exception as e:  # noqa: BLE001
                if _METRICS:
                    _METRICS["svid_load_failures_total"].inc()  # type: ignore[union-attr]
                logger.exception("SVID rotation failed: %s", e)
                # Бэкофф с джиттером
                jitter = random.uniform(0, 0.5)
                sleep_s = min(self._settings.max_refresh_interval.total_seconds(), backoff * (2 + jitter))
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=sleep_s)
                    if self._stop_event.is_set():
                        break
                except asyncio.TimeoutError:
                    pass
                backoff = sleep_s

    async def _next_delay(self) -> float:
        async with self._lock:
            cur = self._cur
            if not cur or not cur.not_after:
                return self._settings.min_refresh_interval.total_seconds()
            # До истечения оставшееся время; рефреш заранее на refresh_skew
            now = datetime.now(tz=timezone.utc)
            refresh_at = cur.not_after - self._settings.refresh_skew
            # Ограничители
            min_i = self._settings.min_refresh_interval
            max_i = self._settings.max_refresh_interval
            if refresh_at <= now:
                return min_i.total_seconds()
            remaining = (refresh_at - now).total_seconds()
            # Варьируем опрос в разумных пределах
            return max(min(remaining, max_i.total_seconds()), min_i.total_seconds())

    async def _refresh_identity(self, initial: bool = False) -> None:
        ident = await self._provider.fetch_x509()
        # Жесткая проверка NotAfter
        if ident.not_after:
            if ident.not_after < datetime.now(tz=timezone.utc) - self._settings.hard_fail_after:
                raise SVIDError("Obtained expired SVID")

        ctx = self._build_ssl_context(ident)

        # Публикация на диск (атомарно)
        await self._publish_identity(ident)

        # Применение состояния и уведомление
        async with self._lock:
            self._cur = ident
            self._ssl_context = ctx
            if _METRICS and ident.not_after:
                _METRICS["svid_not_after_timestamp"].set(ident.not_after.timestamp())  # type: ignore[union-attr]

        # Уведомления подписчиков параллельно, безопасно
        await self._notify_listeners(ident)
        if _METRICS and not initial:
            _METRICS["svid_rotation_events_total"].inc()  # type: ignore[union-attr]
        sid = ident.spiffe_id or "<unknown>"
        na = ident.not_after.isoformat() if ident.not_after else "n/a"
        logger.info("SVID rotated: spiffe_id=%s not_after=%s", sid, na)

    def _build_ssl_context(self, ident: X509Identity) -> ssl.SSLContext:
        # Клиентский контекст для mTLS по умолчанию
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = self._settings.ssl_min_version
        ctx.set_ciphers(self._settings.ssl_ciphers)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = self._settings.verify_hostname

        # Trust bundle
        if ident.trust_bundle_pem:
            # Загружаем bundle через временный файл в memory buffer
            bundle_path = None
            try:
                # ssl не принимает напрямую строку, используем temp файл
                import tempfile
                with tempfile.NamedTemporaryFile("w", delete=False) as tf:
                    tf.write(ident.trust_bundle_pem)
                    bundle_path = tf.name
                ctx.load_verify_locations(cafile=bundle_path)
            finally:
                if bundle_path:
                    try:
                        os.unlink(bundle_path)
                    except Exception:  # noqa: BLE001
                        pass

        # cert chain + key
        # Аналогичная техника с временными файлами, чтобы не хранить ключ на диске, можно использовать memory BIO через PyOpenSSL, но без внешних зависимостей — temp файл.
        import tempfile
        cert_path = key_path = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as cf:
                cf.write(ident.cert_chain_pem)
                cert_path = cf.name
            with tempfile.NamedTemporaryFile("w", delete=False) as kf:
                kf.write(ident.private_key_pem)
                key_path = kf.name
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        finally:
            for p in (cert_path, key_path):
                if p:
                    try:
                        os.unlink(p)
                    except Exception:  # noqa: BLE001
                        pass

        # Усиление профиля
        ctx.options |= (
            ssl.OP_CIPHER_SERVER_PREFERENCE
            | ssl.OP_SINGLE_ECDH_USE
        )
        return ctx

    async def _publish_identity(self, ident: X509Identity) -> None:
        """Опционально публикуем PEM на диск (атомарно), если задан publish_dir."""
        if not self._settings.publish_dir:
            return
        base = self._settings.publish_dir
        base.mkdir(parents=True, exist_ok=True)

        async def _atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(data, encoding="utf-8")
            os.chmod(tmp, mode)
            os.replace(tmp, path)

        await asyncio.to_thread(_atomic_write, base / "svid.pem", ident.cert_chain_pem, 0o644)
        await asyncio.to_thread(_atomic_write, base / "svid.key", ident.private_key_pem, 0o600)
        if ident.trust_bundle_pem:
            await asyncio.to_thread(_atomic_write, base / "bundle.pem", ident.trust_bundle_pem, 0o644)

    async def _notify_listeners(self, ident: X509Identity) -> None:
        if not self._listeners:
            return
        # Запускаем слушателей конкурентно, но контролируем исключения
        async def _run_one(name: str, cb: RotationListener) -> None:
            try:
                await cb(ident)
            except Exception as e:  # noqa: BLE001
                logger.warning("Rotation listener %s failed: %s", name, e)

        await asyncio.gather(*(_run_one(n, cb) for n, cb in self._listeners.items()))


# =========================
# Утилиты и фабрики
# =========================

def settings_from_env(prefix: str = "SVID_") -> SVIDManagerSettings:
    """Считать настройки менеджера из переменных окружения."""
    def _b(name: str, default: bool) -> bool:
        return os.environ.get(prefix + name, str(default)).lower() in ("1", "true", "yes")

    def _p(name: str) -> Optional[Path]:
        v = os.environ.get(prefix + name)
        return Path(v) if v else None

    def _td(name: str, default: int, unit: str = "s") -> timedelta:
        v = int(os.environ.get(prefix + name, str(default)))
        mult = {"s": 1, "m": 60, "h": 3600}[unit]
        return timedelta(seconds=v * mult)

    mode = os.environ.get(prefix + "MODE", "FILE").upper()
    return SVIDManagerSettings(
        mode=mode,
        trust_check_strict=_b("TRUST_STRICT", True),
        file_cert_path=_p("FILE_CERT"),
        file_key_path=_p("FILE_KEY"),
        file_bundle_path=_p("FILE_BUNDLE"),
        spiffe_socket=os.environ.get("SPIFFE_ENDPOINT_SOCKET"),
        trust_domain=os.environ.get(prefix + "TRUST_DOMAIN"),
        min_refresh_interval=_td("MIN_REFRESH_INTERVAL", 15, "s"),
        max_refresh_interval=_td("MAX_REFRESH_INTERVAL", 10, "m"),
        refresh_skew=_td("REFRESH_SKEW", 5, "m"),
        publish_dir=_p("PUBLISH_DIR"),
        verify_hostname=_b("VERIFY_HOSTNAME", False),
    )


# =========================
# Пример запуска как модуля
# =========================

async def _main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    settings = settings_from_env()
    mgr = SVIDManager(settings)
    await mgr.start()

    # Пример слушателя: логирует смену SVID
    async def on_rotate(x: X509Identity) -> None:
        logger.info("Listener: new SVID spiffe_id=%s", x.spiffe_id)

    mgr.add_rotation_listener("log", on_rotate)

    try:
        while True:
            await asyncio.sleep(60)
    except KeyboardInterrupt:
        pass
    finally:
        await mgr.stop()


if __name__ == "__main__":
    if sys.version_info < (3, 11):
        print("Python 3.11+ required", file=sys.stderr)
        sys.exit(2)
    asyncio.run(_main())
