# File: security-core/security/workers/cert_renewer.py
# Purpose: Industrial-grade certificate renewal worker (ACME/internal CA) with safe storage and hooks.
# Python: 3.10+
from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import os
import random
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

# Optional crypto stack (used for key/CSR/parsing). Fails closed with explicit error if missing.
try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    from cryptography.x509.oid import NameOID  # type: ignore
except Exception:
    x509 = hashes = serialization = ec = rsa = ed25519 = default_backend = NameOID = None  # type: ignore


# =========================
# Errors
# =========================

class RenewError(Exception):
    pass

class DependencyMissing(RenewError):
    pass

class SpecError(RenewError):
    pass

class IssuerError(RenewError):
    pass

class StorageError(RenewError):
    pass


# =========================
# Models
# =========================

class KeyType(str):
    RSA = "rsa"
    ECDSA = "ecdsa"
    ED25519 = "ed25519"

@dataclass(frozen=True)
class CertificateBundle:
    private_key_pem: bytes
    certificate_pem: bytes
    chain_pem: bytes
    not_before: datetime
    not_after: datetime
    subject: str
    san_dns: Tuple[str, ...]
    fingerprint_sha256: str

    def fullchain_pem(self) -> bytes:
        # cert + chain in traditional concat order
        return self.certificate_pem + (b"\n" if not self.certificate_pem.endswith(b"\n") else b"") + self.chain_pem

@dataclass(frozen=True)
class Spec:
    id: str
    common_name: str
    dns_names: Tuple[str, ...]
    key_type: KeyType = KeyType.ECDSA
    key_size: int = 256                      # for ECDSA: 256/384; for RSA: 2048/3072/4096
    issuer: str = "acme"                     # "acme" | "internal"
    acme_provider: Optional[str] = None      # "lego" | "acme.sh" | None (for internal)
    acme_env: Mapping[str, str] = dataclasses.field(default_factory=dict)
    contact_email: Optional[str] = None
    renew_before: timedelta = timedelta(days=30)  # renew when now >= not_after - renew_before
    secret_ref: str = ""                     # where to store resulting PEMs
    tenant_id: Optional[str] = None
    tags: Tuple[str, ...] = ()
    disable: bool = False

@dataclass(frozen=True)
class Result:
    spec_id: str
    ok: bool
    message: str
    renewed: bool
    next_check_at: datetime
    not_after: Optional[datetime] = None


# =========================
# Protocols (DI points)
# =========================

class SpecSource(Protocol):
    async def list_specs(self) -> List[Spec]: ...

class Issuer(Protocol):
    async def issue(self, spec: Spec) -> CertificateBundle: ...
    async def renew(self, spec: Spec, existing: CertificateBundle) -> CertificateBundle: ...

class SecretSink(Protocol):
    async def store(self, spec: Spec, bundle: CertificateBundle) -> None: ...
    async def load(self, spec: Spec) -> Optional[CertificateBundle]: ...

class Hook(Protocol):
    async def on_rotated(self, spec: Spec, bundle: CertificateBundle) -> None: ...

class Inhibitor(Protocol):
    async def record_event(self, key: str, *, threshold: int, window_sec: int, cooldown_sec: int) -> bool: ...
    async def is_inhibited(self, key: str) -> bool: ...


# =========================
# Crypto utilities
# =========================

def _require_crypto() -> None:
    if x509 is None:
        raise DependencyMissing("cryptography", "Install with: pip install cryptography")

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _pem_bytes(s: bytes) -> bytes:
    # Normalizes ending newline
    return s if s.endswith(b"\n") else s + b"\n"

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def parse_pem_bundle(priv_pem: bytes, cert_pem: bytes, chain_pem: bytes) -> CertificateBundle:
    _require_crypto()
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    names = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [n.value for n in ext.value.get_values_for_type(x509.DNSName)]
    except Exception:
        names = []
    subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if cert.subject else ""
    fp = _sha256_hex(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    return CertificateBundle(
        private_key_pem=_pem_bytes(priv_pem),
        certificate_pem=_pem_bytes(cert_pem),
        chain_pem=_pem_bytes(chain_pem),
        not_before=not_before,
        not_after=not_after,
        subject=subject,
        san_dns=tuple(names),
        fingerprint_sha256=fp,
    )

def generate_key_and_csr(spec: Spec) -> Tuple[bytes, bytes]:
    _require_crypto()
    # Generate key
    if spec.key_type == KeyType.RSA:
        key = rsa.generate_private_key(public_exponent=65537, key_size=max(2048, spec.key_size), backend=default_backend())
    elif spec.key_type == KeyType.ED25519:
        key = ed25519.Ed25519PrivateKey.generate()
    else:
        curve = ec.SECP256R1() if spec.key_size <= 256 else ec.SECP384R1()
        key = ec.generate_private_key(curve, backend=default_backend())

    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    # CSR
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, spec.common_name)])
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in {spec.common_name, *spec.dns_names}])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return (_pem_bytes(key_pem), _pem_bytes(csr_pem))


# =========================
# Default adapters (SpecSource, SecretSink, Issuers, Hooks)
# =========================

class StaticSpecSource:
    def __init__(self, specs: Sequence[Spec]) -> None:
        self._specs = list(specs)

    async def list_specs(self) -> List[Spec]:
        return [s for s in self._specs]

class FileSecretSink:
    """
    Простое файловое хранилище: кладет key.pem, cert.pem, chain.pem, fullchain.pem в каталог <base>/<spec.id>/
    """
    def __init__(self, base_dir: str) -> None:
        self.base = base_dir

    def _dir(self, spec: Spec) -> str:
        return os.path.join(self.base, spec.id)

    async def store(self, spec: Spec, bundle: CertificateBundle) -> None:
        d = self._dir(spec)
        os.makedirs(d, exist_ok=True)
        # Не логируем содержимое
        with open(os.path.join(d, "key.pem"), "wb") as f:
            f.write(bundle.private_key_pem)
        with open(os.path.join(d, "cert.pem"), "wb") as f:
            f.write(bundle.certificate_pem)
        with open(os.path.join(d, "chain.pem"), "wb") as f:
            f.write(bundle.chain_pem)
        with open(os.path.join(d, "fullchain.pem"), "wb") as f:
            f.write(bundle.fullchain_pem())

    async def load(self, spec: Spec) -> Optional[CertificateBundle]:
        d = self._dir(spec)
        try:
            with open(os.path.join(d, "key.pem"), "rb") as fk, \
                 open(os.path.join(d, "cert.pem"), "rb") as fc, \
                 open(os.path.join(d, "chain.pem"), "rb") as fch:
                return parse_pem_bundle(fk.read(), fc.read(), fch.read())
        except FileNotFoundError:
            return None
        except Exception as e:
            raise StorageError(f"Failed to load PEMs for {spec.id}: {e}")

class ExternalAcmeIssuer:
    """
    Выпуск через внешнюю утилиту (lego или acme.sh).
    Безопасно передает CSR и читает PEM из временного каталога.
    Требует заранее настроенные DNS/HTTP-01 креденшелы в окружении.
    """
    def __init__(self, binary: str = "lego", challenge: str = "dns", extra_args: Sequence[str] = ()) -> None:
        self.binary = binary
        self.challenge = challenge
        self.extra_args = list(extra_args)

    async def issue(self, spec: Spec) -> CertificateBundle:
        key_pem, csr_pem = generate_key_and_csr(spec)
        return await self._run_acme(spec, csr_pem, key_pem)

    async def renew(self, spec: Spec, existing: CertificateBundle) -> CertificateBundle:
        # Для lego/acme.sh «renew» эквивалентен новому выпуску по CSR
        key_pem, csr_pem = generate_key_and_csr(spec)
        return await self._run_acme(spec, csr_pem, key_pem)

    async def _run_acme(self, spec: Spec, csr_pem: bytes, key_pem: bytes) -> CertificateBundle:
        tmpdir = os.path.abspath(os.path.join("/tmp", f"acme_{spec.id}_{int(time.time())}_{random.randint(1000,9999)}"))
        os.makedirs(tmpdir, exist_ok=True)
        csr_path = os.path.join(tmpdir, "req.csr")
        cert_path = os.path.join(tmpdir, "cert.pem")
        chain_path = os.path.join(tmpdir, "chain.pem")
        try:
            with open(csr_path, "wb") as f:
                f.write(csr_pem)
            env = os.environ.copy()
            env.update({k: v for k, v in (spec.acme_env or {}).items()})
            domains: List[str] = [spec.common_name] + [d for d in spec.dns_names if d != spec.common_name]
            dom_args = sum(([f"--domains", d] for d in domains), [])
            if self.binary.endswith("lego"):
                cmd = [self.binary, "--email", spec.contact_email or "", "--csr", csr_path, "--accept-tos", f"--{self.challenge}"] \
                      + self.extra_args + dom_args + ["run"]
                cmd = [c for c in cmd if c != ""]
                await _run_subprocess(cmd, env)
                # lego по CSR пишет fullchain в "./.lego/certificates/*.crt". Для универсальности используем вывод stdout нельзя — поэтому предполагаем chain.pem/cert.pem подготовлены внешним хелпером.
                # Здесь читаем cert_path/chain_path, которые должны быть созданы wrapper-скриптом во время run.
            elif self.binary.endswith("acme.sh"):
                # acme.sh --issue --csr req.csr -d example.com -d www.example.com --fullchain-file cert.pem --ca-file chain.pem
                cmd = [self.binary, "--issue", "--csr", csr_path] + sum((["-d", d] for d in domains), []) \
                      + ["--fullchain-file", cert_path, "--ca-file", chain_path]
                await _run_subprocess(cmd, env)
            else:
                raise IssuerError(f"Unsupported ACME binary: {self.binary}")

            # Читаем PEMы
            if not os.path.exists(cert_path):
                # fallback: попробуем common fullchain
                fullchain_guess = os.path.join(tmpdir, "fullchain.pem")
                if os.path.exists(fullchain_guess):
                    with open(fullchain_guess, "rb") as f:
                        full = f.read()
                    # Разделить fullchain на cert и chain по первому сертификату
                    cert_pem, chain_pem = _split_fullchain(full)
                else:
                    raise IssuerError("Certificate file not found")
            else:
                with open(cert_path, "rb") as f:
                    cert_pem = f.read()
                with open(chain_path, "rb") as f:
                    chain_pem = f.read()

            return parse_pem_bundle(key_pem, cert_pem, chain_pem)
        finally:
            try:
                for fn in ["req.csr", "cert.pem", "chain.pem", "fullchain.pem"]:
                    p = os.path.join(tmpdir, fn)
                    if os.path.exists(p):
                        os.remove(p)
                os.rmdir(tmpdir)
            except Exception:
                pass

def _split_fullchain(full: bytes) -> Tuple[bytes, bytes]:
    parts = re.findall(br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*", full, flags=re.S)
    if not parts:
        raise IssuerError("Invalid fullchain format")
    return parts[0], b"".join(parts[1:]) if len(parts) > 1 else b""

async def _run_subprocess(cmd: Sequence[str], env: Mapping[str, str]) -> None:
    proc = await asyncio.create_subprocess_exec(*cmd, env=dict(env), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0:
        raise IssuerError(f"ACME command failed: {cmd!r}: {err.decode(errors='ignore')[:4000]}")

class NoopHook:
    async def on_rotated(self, spec: Spec, bundle: CertificateBundle) -> None:
        return

class HttpWebhookHook:
    """
    Отправляет POST с JSON, подписанный HMAC-SHA256, в ваш endpoint.
    """
    def __init__(self, url: str, secret: str, timeout: float = 5.0) -> None:
        self.url = url
        self.secret = secret.encode("utf-8")
        self.timeout = timeout

    async def on_rotated(self, spec: Spec, bundle: CertificateBundle) -> None:
        try:
            import aiohttp  # type: ignore
        except Exception:
            # Без зависимостей просто пропускаем с мягкой ошибкой
            raise StorageError("aiohttp is required for HttpWebhookHook")
        payload = {
            "spec_id": spec.id,
            "not_after": bundle.not_after.isoformat(),
            "fingerprint_sha256": bundle.fingerprint_sha256,
            "dns": list(bundle.san_dns),
            "tenant": spec.tenant_id,
            "tags": list(spec.tags),
        }
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        sig = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as sess:
            async with sess.post(self.url, data=body, headers={"Content-Type": "application/json", "X-Signature": sig}) as resp:
                if resp.status >= 400:
                    raise StorageError(f"Webhook responded {resp.status}")

class CommandHook:
    """
    Запускает локальную команду для graceful reload (например, nginx -s reload).
    """
    def __init__(self, command: Sequence[str]) -> None:
        self.command = list(command)

    async def on_rotated(self, spec: Spec, bundle: CertificateBundle) -> None:
        proc = await asyncio.create_subprocess_exec(*self.command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        _, err = await proc.communicate()
        if proc.returncode != 0:
            raise StorageError(f"Reload command failed: {err.decode(errors='ignore')[:4000]}")

class SimpleInhibitor:
    """
    Локальный ингибитор: окно + cooldown. Для продакшена подключите ваш redis-бэкенд.
    """
    def __init__(self) -> None:
        self._ban: dict[str, int] = {}

    async def record_event(self, key: str, *, threshold: int, window_sec: int, cooldown_sec: int) -> bool:
        now = int(time.time())
        ttl = self._ban.get(key, 0)
        if now < ttl:
            return True
        # простой порог: сразу баним на cooldown; реализация со счетчиком опущена
        self._ban[key] = now + cooldown_sec
        return False

    async def is_inhibited(self, key: str) -> bool:
        return int(time.time()) < self._ban.get(key, 0)


# =========================
# Metrics (best-effort; works without deps)
# =========================

class _Metrics:
    def __init__(self) -> None:
        self.enabled = True

    def inc(self, name: str, labels: Mapping[str, str]) -> None:
        # Plug your metrics backend here
        return

    def observe(self, name: str, value: float, labels: Mapping[str, str]) -> None:
        return

METRICS = _Metrics()


# =========================
# Planner and worker
# =========================

@dataclass
class BackoffState:
    strikes: int = 0
    last_error: Optional[str] = None

class CertRenewerWorker:
    """
    Планировщик и исполнитель ротаций. Идempotent, устойчив к рестартам.
    """
    def __init__(
        self,
        specs: SpecSource,
        issuer: Issuer,
        sink: SecretSink,
        *,
        hook: Optional[Hook] = None,
        inhibitor: Optional[Inhibitor] = None,
        interval_sec: int = 60,
        jitter_sec: int = 15,
        threshold_failures: int = 3,
        backoff_base_sec: int = 60,
        backoff_max_sec: int = 3600,
        safety_window_min: timedelta = timedelta(days=7),
    ) -> None:
        self.specs = specs
        self.issuer = issuer
        self.sink = sink
        self.hook = hook or NoopHook()
        self.inhibitor = inhibitor or SimpleInhibitor()
        self.interval_sec = interval_sec
        self.jitter_sec = jitter_sec
        self.threshold_failures = threshold_failures
        self.backoff_base_sec = backoff_base_sec
        self.backoff_max_sec = backoff_max_sec
        self.safety_window_min = safety_window_min
        self._backoff: dict[str, BackoffState] = {}

    async def run_forever(self, *, stop_event: Optional[asyncio.Event] = None) -> None:
        """
        Основной цикл: периодически опрашивает спецификации и запускает ротации по необходимости.
        """
        stop_event = stop_event or asyncio.Event()
        while not stop_event.is_set():
            try:
                await self._iteration()
            except Exception as e:
                # Не «падаем» из-за одной ошибки; логируйте при интеграции
                pass
            # Пауза с джиттером
            await asyncio.wait_for(asyncio.sleep(self._with_jitter(self.interval_sec)), timeout=None)

    async def _iteration(self) -> None:
        all_specs = [s for s in await self.specs.list_specs() if not s.disable]
        now = _utcnow()
        tasks = []
        for s in all_specs:
            # Проверяем текущий бандл (если есть)
            existing = await self.sink.load(s)
            if existing:
                renew_at = max(existing.not_after - s.renew_before, now)  # не раньше текущего времени
                # Учитываем минимальное окно безопасности
                renew_at = min(renew_at, existing.not_after - self.safety_window_min)
            else:
                # Нет сертификата — требуется немедленный выпуск
                renew_at = now

            if now >= renew_at:
                tasks.append(self._renew_one(s, existing))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _renew_one(self, spec: Spec, existing: Optional[CertificateBundle]) -> Result:
        start = time.perf_counter()
        spec_key = f"cert-renew:{spec.id}"
        # Ингибитор: если недавно валились, делаем паузу
        if await self.inhibitor.is_inhibited(spec_key):
            return Result(spec.id, ok=False, message="inhibited", renewed=False, next_check_at=_utcnow() + timedelta(seconds=self.backoff_base_sec))

        try:
            if existing is None:
                bundle = await self.issuer.issue(spec)
            else:
                bundle = await self.issuer.renew(spec, existing)

            # Безопасное сохранение
            await self.sink.store(spec, bundle)

            # Хук после ротации
            try:
                await self.hook.on_rotated(spec, bundle)
            except Exception as hook_err:
                # Хук не должен срывать ротацию: фиксируем, но продолжаем
                self._remember_error(spec.id, f"hook: {hook_err}")

            self._clear_backoff(spec.id)
            METRICS.inc("cert_renew_success_total", {"issuer": spec.issuer})
            METRICS.observe("cert_renew_duration_seconds", time.perf_counter() - start, {"issuer": spec.issuer})
            return Result(
                spec.id,
                ok=True,
                message="renewed",
                renewed=True,
                next_check_at=min(bundle.not_after - spec.renew_before, bundle.not_after - self.safety_window_min),
                not_after=bundle.not_after,
            )
        except Exception as e:
            # Ошибка — увеличиваем backoff
            bs = self._remember_error(spec.id, str(e))
            delay = min(self.backoff_max_sec, int(self.backoff_base_sec * (2 ** min(6, bs.strikes))))
            await self.inhibitor.record_event(spec_key, threshold=self.threshold_failures, window_sec=delay, cooldown_sec=delay)
            METRICS.inc("cert_renew_failure_total", {"issuer": spec.issuer})
            return Result(
                spec.id,
                ok=False,
                message=f"error: {e}",
                renewed=False,
                next_check_at=_utcnow() + timedelta(seconds=delay),
                not_after=existing.not_after if existing else None,
            )

    def _remember_error(self, spec_id: str, msg: str) -> BackoffState:
        st = self._backoff.get(spec_id) or BackoffState()
        st = BackoffState(strikes=st.strikes + 1, last_error=msg)
        self._backoff[spec_id] = st
        return st

    def _clear_backoff(self, spec_id: str) -> None:
        self._backoff.pop(spec_id, None)

    def _with_jitter(self, base: int) -> float:
        if self.jitter_sec <= 0:
            return float(base)
        return float(base + random.uniform(-self.jitter_sec, self.jitter_sec))


# =========================
# Helpers: minimal PEM I/O safety
# =========================

_PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
_PEM_KEY_RE = re.compile(rb"-----BEGIN (?:EC|RSA|PRIVATE) KEY-----.*?-----END (?:EC|RSA|PRIVATE) KEY-----", re.S)

def validate_pem_pair(cert_pem: bytes, key_pem: bytes) -> None:
    if not _PEM_CERT_RE.search(cert_pem):
        raise StorageError("Invalid certificate PEM")
    if not _PEM_KEY_RE.search(key_pem):
        raise StorageError("Invalid key PEM")


# =========================
# Example wiring factory (optional)
# =========================

def build_default_worker(
    specs: Sequence[Spec],
    *,
    storage_dir: str = "/etc/ssl/managed",
    acme_bin: str = "acme.sh",
    acme_challenge: str = "dns",
    hook_cmd: Optional[Sequence[str]] = None,
) -> CertRenewerWorker:
    """
    Упрощенный конструктор воркера: статические спецификации, файловое хранилище и внешняя ACME-утилита.
    """
    issuer = ExternalAcmeIssuer(binary=acme_bin, challenge=acme_challenge)
    sink = FileSecretSink(storage_dir)
    hook = CommandHook(hook_cmd) if hook_cmd else NoopHook()
    return CertRenewerWorker(StaticSpecSource(specs), issuer, sink, hook=hook)


# =========================
# If run as script (demo only)
# =========================

async def _demo() -> None:
    # Пример одной спецификации
    sp = Spec(
        id="example-com",
        common_name="example.com",
        dns_names=("www.example.com",),
        key_type=KeyType.ECDSA,
        key_size=256,
        issuer="acme",
        acme_provider="acme.sh",
        contact_email="admin@example.com",
        secret_ref="/etc/ssl/managed/example-com",
        renew_before=timedelta(days=30),
    )
    worker = build_default_worker([sp], storage_dir="/tmp/ssl", acme_bin="acme.sh", acme_challenge="dns")
    stop = asyncio.Event()
    # Останов через 5 минут (демо)
    async def _stopper():
        await asyncio.sleep(300)
        stop.set()
    asyncio.create_task(_stopper())
    await worker.run_forever(stop_event=stop)

if __name__ == "__main__":
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass
