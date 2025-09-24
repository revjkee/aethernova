# physical-integration-core/physical_integration/edge/enrollment.py
from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import random
import ssl
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from uuid import UUID, uuid4, uuid5, NAMESPACE_DNS

LOG = logging.getLogger("physical_integration.edge.enrollment")

# -----------------------------
# Опциональные зависимости
# -----------------------------
# Криптография (обязательно для CSR/ключей при отсутствии TPM)
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.x509.oid import NameOID
except Exception:  # pragma: no cover
    x509 = default_backend = hashes = serialization = ec = ed25519 = NameOID = None  # type: ignore

# TPM2 (если есть)
try:
    from tpm2_pytss import ESYS_TR, TPM2_ALG, TPMT_PUBLIC, TPM2B_PUBLIC, TPM2B_DATA, TctiLdr, ESAPI  # type: ignore
    _TPM_AVAILABLE = True
except Exception:  # pragma: no cover
    ESYS_TR = TPM2_ALG = TPMT_PUBLIC = TPM2B_PUBLIC = TPM2B_DATA = TctiLdr = ESAPI = None  # type: ignore
    _TPM_AVAILABLE = False

# HTTP клиент: httpx (если установлен) или urllib в качестве фолбэка
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore
    import urllib.request
    import urllib.error
    import urllib.parse


# -----------------------------
# Исключения
# -----------------------------
class EnrollmentError(Exception):
    pass


# -----------------------------
# Настройки
# -----------------------------
@dataclass
class Settings:
    base_url: str = os.getenv("ENROLL_BASE_URL", "https://controller.local")
    # Точка подачи CSR (должна принимать JSON с полями ниже). Конкретный путь вашей системы задаётся извне.
    enroll_endpoint: str = os.getenv("ENROLL_RA_ENDPOINT", "/api/v1/enroll/csr")
    # Опциональный endpoint «ensure twin», если хотите создать запись устройства на стороне контроллера.
    twin_ensure_endpoint: str = os.getenv("TWIN_ENSURE_ENDPOINT", "/api/v1/twin/{device_id}:ensure")
    # Директория для ключей/сертов/состояния
    data_dir: Path = Path(os.getenv("ENROLL_DATA_DIR", "/var/lib/physical-integration/enroll")).resolve()
    keys_dir: Path = Path(os.getenv("ENROLL_KEYS_DIR", "/etc/physical-integration/keys")).resolve()
    # Алгоритм ключа по умолчанию при отсутствии TPM: ed25519 | ecdsa-p256
    sw_key_algo: str = os.getenv("ENROLL_SW_KEY_ALGO", "ed25519")
    # Срок обновления до истечения (дни)
    renew_before_days: int = int(os.getenv("ENROLL_RENEW_BEFORE_DAYS", "30"))
    # User-Agent
    user_agent: str = os.getenv("ENROLL_USER_AGENT", "physical-integration-enroll/1.0")
    # Тайм-ауты и повторы
    http_timeout_sec: int = int(os.getenv("ENROLL_HTTP_TIMEOUT", "15"))
    backoff_base: float = float(os.getenv("ENROLL_BACKOFF_BASE", "0.5"))
    backoff_cap: float = float(os.getenv("ENROLL_BACKOFF_CAP", "30"))
    # MTLS после установки сертификата — куда он кладётся
    cert_path: Path = Path(os.getenv("ENROLL_CERT_PATH", "") or "")
    key_path: Path = Path(os.getenv("ENROLL_KEY_PATH", "") or "")
    ca_bundle_path: Optional[Path] = Path(os.getenv("ENROLL_CA_BUNDLE", "")) if os.getenv("ENROLL_CA_BUNDLE") else None
    # Организация в Subject CSR (опционально)
    subject_org: Optional[str] = os.getenv("ENROLL_SUBJECT_ORG") or None
    # Имя устройства для Twin ensure (необязательно)
    display_name: Optional[str] = os.getenv("ENROLL_DISPLAY_NAME") or None
    vendor: Optional[str] = os.getenv("ENROLL_VENDOR") or None


# -----------------------------
# Состояние
# -----------------------------
@dataclass
class EnrollmentState:
    device_id: str
    # Где лежат ключ и сертификат
    key_path: str
    cert_path: Optional[str] = None
    chain_path: Optional[str] = None
    # Срок действия
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    # Этапы
    installed: bool = False
    last_enroll_at: Optional[str] = None
    last_error: Optional[str] = None

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(dataclasses.asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

    @staticmethod
    def load(path: Path) -> Optional["EnrollmentState"]:
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return EnrollmentState(**data)
        except Exception:
            return None


# -----------------------------
# Утилиты
# -----------------------------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_mode_600(p: Path) -> None:
    try:
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def _read_text_first(path: Path) -> Optional[str]:
    with contextlib.suppress(Exception):
        return path.read_text(encoding="utf-8").strip()
    return None


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _jittered_backoff(retry: int, base: float, cap: float) -> float:
    return random.uniform(0, min(cap, base * (2 ** retry)))


def _stable_device_fingerprint() -> str:
    """
    Формирует стабильный отпечаток устройства из доступных фактов:
    MAC адреса, серийный номер, dmi/product_uuid, imei (если присутствует).
    Всё это — best-effort; на некоторых платформах возможны заглушки.
    """
    facts: Dict[str, str] = {}
    # MAC адреса
    try:
        for iface in os.listdir("/sys/class/net"):
            with contextlib.suppress(Exception):
                mac = Path(f"/sys/class/net/{iface}/address").read_text(encoding="utf-8").strip()
                if mac and mac != "00:00:00:00:00:00":
                    facts[f"mac:{iface}"] = mac.lower()
    except Exception:
        pass

    # Серийный номер/UUID платформы
    for candidate in [
        Path("/sys/class/dmi/id/product_serial"),
        Path("/sys/class/dmi/id/product_uuid"),
        Path("/proc/cpuinfo"),  # на ARM иногда содержит Serial
    ]:
        v = _read_text_first(candidate)
        if v:
            facts[f"file:{candidate.name}"] = v

    # На совершенно «голых» системах fallback на случайный, но фиксируемый в файле
    seed_file = Path("/var/lib/physical-integration/enroll/device.seed")
    seed_file.parent.mkdir(parents=True, exist_ok=True)
    if not seed_file.exists():
        seed_file.write_text(str(uuid4()), encoding="utf-8")
    seed = seed_file.read_text(encoding="utf-8").strip()

    payload = json.dumps(facts, sort_keys=True).encode("utf-8") + seed.encode("utf-8")
    # UUIDv5 от домена и фактов — стабильный, предсказуемый при неизменных фактах и seed
    return str(uuid5(NAMESPACE_DNS, _sha256_hex(payload)))


def _build_subject(device_id: str, org: Optional[str]) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, device_id)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


# -----------------------------
# Ключи/CSR: TPM и программный
# -----------------------------
class KeyProvider:
    def __init__(self, st: Settings, device_id: str):
        self.st = st
        self.device_id = device_id
        self.keys_dir = st.keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        # Путь по умолчанию, если не задано явно
        self.key_path = st.key_path or (self.keys_dir / f"{device_id}.key")
        self.cert_path = st.cert_path or (self.keys_dir / f"{device_id}.crt")
        self.chain_path = self.keys_dir / f"{device_id}.chain.pem"

    # --- программные ключи ---
    def _ensure_sw_key(self) -> serialization.PrivateFormat:
        if self.key_path.exists():
            pem = self.key_path.read_bytes()
            try:
                return serialization.load_pem_private_key(pem, password=None, backend=default_backend())
            except Exception as ex:  # pragma: no cover
                raise EnrollmentError(f"failed to load existing key: {ex}")

        algo = self.st.sw_key_algo.lower()
        if algo == "ed25519":
            priv = ed25519.Ed25519PrivateKey.generate()
        elif algo in ("ecdsa-p256", "p256", "ecdsa"):
            priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        else:
            raise EnrollmentError(f"unsupported sw key algo: {self.st.sw_key_algo}")

        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_path.write_bytes(pem)
        _ensure_mode_600(self.key_path)
        LOG.info("Generated software key: %s", self.key_path)
        return priv

    def _csr_from_sw(self, subject: x509.Name, san_dns: Optional[str] = None) -> Tuple[bytes, bytes]:
        priv = self._ensure_sw_key()
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        if san_dns:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=False)
        csr = builder.sign(priv, hashes.SHA256(), default_backend())
        pem = csr.public_bytes(serialization.Encoding.PEM)
        return pem, self.key_path.read_bytes()

    # --- TPM2 ключи (минимальный каркас; CSR подписывается вне TPM ограничений) ---
    def _tpm_available(self) -> bool:
        return _TPM_AVAILABLE

    def _csr_from_tpm(self, subject: x509.Name) -> Tuple[bytes, bytes, Dict[str, Any]]:
        """
        Возвращает CSR PEM, заглушку на ключевой материал (не используется),
        а также аттестационное доказательство (evidence), которое сервер может верифицировать.
        Реализация зависит от вашей PKI: здесь приводится минимальная заглушка с quote через tpm2-tools.
        """
        # Попытка получить quote из tpm2-tools (как самый совместимый путь)
        evidence: Dict[str, Any] = {}
        try:
            pcr_list = os.getenv("ENROLL_TPM_PCRS", "0,7").split(",")
            pcrs = ",".join(str(int(x)) for x in pcr_list)
            # tpm2_pcrread требует доступ к tpm2-tools
            quote_file = self.st.data_dir / "tpm_quote.bin"
            aik_ctx = self.st.data_dir / "aik.ctx"
            self.st.data_dir.mkdir(parents=True, exist_ok=True)
            # Ниже — пример; в вашем проде используйте более строгий процесс подготовки AK/AIK
            subprocess.run(["tpm2_createak", "-C", "o", "-c", str(aik_ctx), "-G", "rsa", "-g", "sha256", "-s", "rsassa"], check=True)
            subprocess.run(["tpm2_quote", "-c", str(aik_ctx), "-l", f"sha256:{pcrs}", "-q", "enroll", "-m", str(quote_file)], check=True)
            evidence["tpm_quote_b64"] = base64.b64encode(quote_file.read_bytes()).decode("ascii")
            evidence["aik_pub_b64"] = base64.b64encode(subprocess.check_output(["tpm2_readpublic", "-c", str(aik_ctx), "-o", "-"])
                                                      ).decode("ascii")
        except Exception as ex:  # pragma: no cover
            LOG.warning("TPM evidence not available: %s", ex)

        # CSR всё равно формируем на программном ключе (распространённая практика для mTLS клиента)
        pem, key = self._csr_from_sw(subject)
        return pem, key, evidence


# -----------------------------
# HTTP клиент (httpx | urllib)
# -----------------------------
class HttpClient:
    def __init__(self, st: Settings):
        self.st = st

    def _headers(self) -> Dict[str, str]:
        return {"User-Agent": self.st.user_agent, "Content-Type": "application/json"}

    async def post_json(self, path: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        url = self.st.base_url.rstrip("/") + path
        if httpx:
            async with httpx.AsyncClient(timeout=self.st.http_timeout_sec, verify=self.st.ca_bundle_path or True) as cli:
                r = await cli.post(url, headers=self._headers(), json=payload)
                data = r.json() if r.content else {}
                return r.status_code, data  # type: ignore
        # urllib fallback
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.st.http_timeout_sec) as resp:
                body = resp.read()
                return resp.status, json.loads(body.decode("utf-8")) if body else {}
        except urllib.error.HTTPError as e:  # type: ignore
            body = e.read()
            try:
                return e.code, json.loads(body.decode("utf-8"))
            except Exception:
                return e.code, {"error": body.decode("utf-8")}
        except Exception as ex:
            raise EnrollmentError(f"HTTP POST failed: {ex}")

    async def get_json(self, path: str) -> Tuple[int, Dict[str, Any]]:
        url = self.st.base_url.rstrip("/") + path
        if httpx:
            async with httpx.AsyncClient(timeout=self.st.http_timeout_sec, verify=self.st.ca_bundle_path or True) as cli:
                r = await cli.get(url, headers=self._headers())
                data = r.json() if r.content else {}
                return r.status_code, data  # type: ignore
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.st.http_timeout_sec) as resp:
                body = resp.read()
                return resp.status, json.loads(body.decode("utf-8")) if body else {}
        except urllib.error.HTTPError as e:  # type: ignore
            body = e.read()
            try:
                return e.code, json.loads(body.decode("utf-8"))
            except Exception:
                return e.code, {"error": body.decode("utf-8")}
        except Exception as ex:
            raise EnrollmentError(f"HTTP GET failed: {ex}")


# -----------------------------
# Клиент регистрации
# -----------------------------
class EnrollmentClient:
    def __init__(self, settings: Optional[Settings] = None):
        self.st = settings or Settings()
        self.state_path = self.st.data_dir / "state.json"
        self.state: Optional[EnrollmentState] = EnrollmentState.load(self.state_path)
        if not self.state:
            device_id = _stable_device_fingerprint()
            self.state = EnrollmentState(
                device_id=device_id,
                key_path=str((self.st.keys_dir / f"{device_id}.key").resolve()),
            )
            self.state.save(self.state_path)
        self.kp = KeyProvider(self.st, self.state.device_id)  # type: ignore
        self.http = HttpClient(self.st)

    # --- основной цикл ---
    async def run_forever(self) -> None:
        retry = 0
        while True:
            try:
                await self.ensure_enrolled()
                # Планируем продление
                delay = await self._seconds_until_renew()
                LOG.info("Enrollment ok. Next renewal check in %.0fs", delay)
                await asyncio.sleep(delay)
                retry = 0
            except asyncio.CancelledError:
                raise
            except Exception as ex:
                LOG.error("Enrollment loop error: %s", ex)
                self.state.last_error = str(ex)
                self.state.save(self.state_path)
                delay = _jittered_backoff(retry, self.st.backoff_base, self.st.backoff_cap)
                await asyncio.sleep(delay)
                retry += 1

    # --- по шагам ---
    async def ensure_enrolled(self) -> None:
        # Если сертификат уже установлен и не близок к истечению, ничего не делаем
        if self.state.installed and not self._close_to_expiry():
            return

        # 1. Ensure twin record (опционально)
        await self._ensure_twin()

        # 2. Сформировать CSR и собрать факты
        subject = _build_subject(self.state.device_id, self.st.subject_org)  # type: ignore
        if _TPM_AVAILABLE and os.getenv("ENROLL_USE_TPM", "true").lower() in {"1", "true", "yes"}:
            csr_pem, key_bytes, evidence = self.kp._csr_from_tpm(subject)
        else:
            if x509 is None:  # pragma: no cover
                raise EnrollmentError("cryptography package is required but not available")
            csr_pem, key_bytes = self.kp._csr_from_sw(subject)
            evidence = {}

        payload = {
            "device_id": self.state.device_id,
            "csr_pem_b64": base64.b64encode(csr_pem).decode("ascii"),
            "facts": self._collect_facts(),
            "evidence": evidence,
        }

        # 3. Подать заявку
        status, data = await self.http.post_json(self.st.enroll_endpoint, payload)
        if status not in (200, 201, 202):
            raise EnrollmentError(f"enroll submit failed: {status} {data}")

        # Ожидаемые варианты ответов:
        # - 201/200: {"certificate_pem":"...", "chain_pem":"..."} — немедленная выдача
        # - 202: {"poll":"<path>"} — надо опрашивать до готовности
        cert_pem = None
        chain_pem = None
        if "certificate_pem" in data:
            cert_pem = data.get("certificate_pem")
            chain_pem = data.get("chain_pem")
        elif "poll" in data:
            poll_path = str(data["poll"])
            cert_pem, chain_pem = await self._poll_certificate(poll_path)
        else:
            raise EnrollmentError("unexpected RA response format")

        # 4. Установить материалы
        self._install_materials(key_bytes, cert_pem.encode("utf-8"), chain_pem.encode("utf-8") if chain_pem else None)

        # 5. Обновить состояние
        nb, na = _parse_cert_dates(cert_pem)
        self.state.not_before = nb.isoformat() if nb else None
        self.state.not_after = na.isoformat() if na else None
        self.state.installed = True
        self.state.last_enroll_at = _utcnow().isoformat()
        self.state.last_error = None
        self.state.save(self.state_path)
        LOG.info("Enrollment installed. NotAfter=%s", self.state.not_after)

    async def _ensure_twin(self) -> None:
        path = self.st.twin_ensure_endpoint.format(device_id=self.state.device_id)
        payload = {"display_name": self.st.display_name, "vendor": self.st.vendor}
        # Вариант «ensure» должен быть идемпотентным на стороне сервера; здесь ошибка — не фатальна.
        with contextlib.suppress(Exception):
            status, _ = await self.http.post_json(path, payload)
            if status not in (200, 201, 409):
                LOG.warning("twin ensure returned %s", status)

    async def _poll_certificate(self, poll_path: str) -> Tuple[str, Optional[str]]:
        retry = 0
        while True:
            status, data = await self.http.get_json(poll_path)
            if status == 200 and "certificate_pem" in data:
                return data["certificate_pem"], data.get("chain_pem")
            if status in (204, 202):
                await asyncio.sleep(_jittered_backoff(retry, self.st.backoff_base, self.st.backoff_cap))
                retry += 1
                continue
            raise EnrollmentError(f"poll failed: {status} {data}")

    def _install_materials(self, key_bytes: bytes, cert_pem: bytes, chain_pem: Optional[bytes]) -> None:
        key_path = Path(self.kp.key_path)
        cert_path = Path(self.kp.cert_path)
        chain_path = Path(self.kp.chain_path)

        # Ключ уже должен лежать (для sw). Если TPM — он не используется для TLS напрямую в этой заготовке.
        if not key_path.exists():
            key_path.write_bytes(key_bytes)
            _ensure_mode_600(key_path)

        cert_path.write_bytes(cert_pem)
        _ensure_mode_600(cert_path)

        if chain_pem:
            chain_path.write_bytes(chain_pem)
            _ensure_mode_600(chain_path)

        # Обновим в state абсолютные пути
        self.state.key_path = str(key_path.resolve())
        self.state.cert_path = str(cert_path.resolve())
        if chain_pem:
            self.state.chain_path = str(chain_path.resolve())

    def _close_to_expiry(self) -> bool:
        if not self.state.not_after:
            return True
        try:
            na = datetime.fromisoformat(self.state.not_after)
        except Exception:
            return True
        return _utcnow() >= (na - timedelta(days=self.st.renew_before_days))

    async def _seconds_until_renew(self) -> float:
        if not self.state.not_after:
            return _jittered_backoff(0, self.st.backoff_base, self.st.backoff_cap)
        try:
            na = datetime.fromisoformat(self.state.not_after)
        except Exception:
            return _jittered_backoff(0, self.st.backoff_base, self.st.backoff_cap)
        target = na - timedelta(days=self.st.renew_before_days)
        now = _utcnow()
        if target <= now:
            return _jittered_backoff(0, self.st.backoff_base, self.st.backoff_cap)
        return max(5.0, (target - now).total_seconds())

    def _collect_facts(self) -> Dict[str, Any]:
        facts: Dict[str, Any] = {
            "device_id": self.state.device_id,
            "hostname": os.uname().nodename if hasattr(os, "uname") else None,
            "platform": sys.platform,
        }
        # MAC адреса
        try:
            macs = {}
            for iface in os.listdir("/sys/class/net"):
                with contextlib.suppress(Exception):
                    mac = Path(f"/sys/class/net/{iface}/address").read_text(encoding="utf-8").strip()
                    if mac and mac != "00:00:00:00:00:00":
                        macs[iface] = mac.lower()
            if macs:
                facts["macs"] = macs
        except Exception:
            pass

        # DMI
        for k, p in {
            "dmi_product_serial": Path("/sys/class/dmi/id/product_serial"),
            "dmi_product_uuid": Path("/sys/class/dmi/id/product_uuid"),
        }.items():
            v = _read_text_first(p)
            if v:
                facts[k] = v
        return facts


# -----------------------------
# Сертификаты: парсинг дат
# -----------------------------
def _parse_cert_dates(cert_pem: str) -> Tuple[Optional[datetime], Optional[datetime]]:
    if x509 is None:  # pragma: no cover
        return None, None
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"), default_backend())
        return cert.not_valid_before.replace(tzinfo=timezone.utc), cert.not_valid_after.replace(tzinfo=timezone.utc)
    except Exception:
        return None, None


# -----------------------------
# CLI
# -----------------------------
def _setup_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    json_mode = os.getenv("LOG_JSON", "true").lower() in {"1", "true", "yes"}
    h = logging.StreamHandler()
    if json_mode:
        class _JsonFmt(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                data = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "msg": record.getMessage(),
                }
                if record.exc_info:
                    data["exc"] = self.formatException(record.exc_info)
                return json.dumps(data, ensure_ascii=False)
        h.setFormatter(_JsonFmt())
    else:
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(getattr(logging, level, logging.INFO))


async def _amain() -> None:
    _setup_logging()
    st = Settings()
    client = EnrollmentClient(st)
    await client.run_forever()


def main() -> None:
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
