# cybersecurity-core/cybersecurity/deception/honeytoken.py
"""
Industrial Honeytoken Toolkit (stdlib only).

Назначение:
- Генерация и верификация honeytoken'ов с криптографической подписью (HMAC-SHA256).
- Форматы: канонический (HTK1-<id>-<sig>), URL-маячок, «псевдо-AWS» ключи, «псевдо-GitHub» токены,
  встраиваемые строки в .env/ini-конфиги и DB-строки.
- Мультиарендность: tenant_id, теги, метаданные, срок действия, стабильные отпечатки.
- Декодирование/сканирование текстов и логов: извлечение, проверка подписи, нормализованное событие.
- Ротация/отзыв: генерация нового токена на базе старого контекста, маркировка revoked.
- Интеграция: безопасные структуры событий для SIEM/SOAR/EDR пайплайна.

Безопасность:
- Токены НЕ дают доступов; значения выглядят реалистично, но невалидны и содержат проверяемую подпись.
- Подпись HMAC-SHA256 по (tenant_id | kind | id | created_at) + секрет.
- Секрет берётся из env HONEYTOKEN_SECRET. При отсутствии используется эфемерный секрет (подходит для dev).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


# --------------------------------------------------------------------------------------
# Конфигурация/секрет
# --------------------------------------------------------------------------------------

def _b32(b: bytes) -> str:
    return base64.b32encode(b).decode("ascii").rstrip("=")

def _b32_decode(s: str) -> bytes:
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s + pad, casefold=True)

_SECRET = os.getenv("HONEYTOKEN_SECRET", None)
_DEV_SECRET = None
if not _SECRET:
    # Эфемерный секрет для dev/тестов. В проде использовать HONEYTOKEN_SECRET.
    _DEV_SECRET = secrets.token_bytes(32)
    _SECRET = base64.b64encode(_DEV_SECRET).decode("ascii")

def _secret_bytes() -> bytes:
    try:
        return base64.b64decode(_SECRET)
    except Exception:
        # fallback, если переменная установлена не в base64
        return _SECRET.encode("utf-8")


# --------------------------------------------------------------------------------------
# Типы/модели
# --------------------------------------------------------------------------------------

class HoneytokenType(str, Enum):
    CANONICAL = "canonical"            # "HTK1-<id>-<sig>"
    URL = "url"                        # "https://example.invalid/honey/<token>?s=<sig>"
    AWS_FAKE = "aws_fake"              # Похож на AWS, но содержит канонический токен внутри секрета/комментария
    GITHUB_FAKE = "github_fake"        # ghp_... + канонический токен в хвосте/комментарии
    ENV_FILE = "env_file"              # Текстовый .env с фальшивыми переменными и внедрённым токеном
    INI_FILE = "ini_file"              # Текстовый .ini/credentials
    DB_CONN = "db_conn"                # Строка подключения с параметром htk=...

class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Recommendation(str, Enum):
    ALERT_ONLY = "alert_only"
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    BLOCK_IP = "block_ip"

@dataclass
class Honeytoken:
    token_id: str               # base32(10 bytes) ~ 16 симв.
    tenant_id: str
    kind: HoneytokenType
    label: str
    signature: str              # base32(10 bytes) ~ 16 симв.
    created_at: datetime
    expires_at: Optional[datetime] = None
    tags: Tuple[str, ...] = field(default_factory=tuple)
    metadata: Dict[str, Any] = field(default_factory=dict)
    revoked: bool = False

    def canonical(self) -> str:
        return f"HTK1-{self.token_id}-{self.signature}"

    def fingerprint(self) -> str:
        payload = {
            "tid": self.tenant_id,
            "kid": self.kind.value,
            "id": self.token_id,
            "sig": self.signature,
            "created": self.created_at.isoformat(),
            "expires": self.expires_at.isoformat() if self.expires_at else None,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        now = now or datetime.now(timezone.utc)
        return now >= self.expires_at

    def serialize(self) -> str:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["created_at"] = self.created_at.isoformat()
        if d["expires_at"]:
            d["expires_at"] = self.expires_at.isoformat()  # type: ignore
        return json.dumps(d, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def deserialize(s: str) -> "Honeytoken":
        d = json.loads(s)
        return Honeytoken(
            token_id=d["token_id"],
            tenant_id=d["tenant_id"],
            kind=HoneytokenType(d["kind"]),
            label=d["label"],
            signature=d["signature"],
            created_at=datetime.fromisoformat(d["created_at"]),
            expires_at=datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None,
            tags=tuple(d.get("tags", [])),
            metadata=d.get("metadata", {}),
            revoked=bool(d.get("revoked", False)),
        )

@dataclass
class GeneratedArtifacts:
    """Производные представления токена для размещения."""
    canonical: str
    url: Optional[str] = None
    aws: Optional[Dict[str, str]] = None
    github: Optional[str] = None
    env_text: Optional[str] = None
    ini_text: Optional[str] = None
    db_conn: Optional[str] = None

@dataclass
class HitEvent:
    """Нормализованное событие сработки honeytoken'а (для SIEM/SOAR)."""
    tenant_id: str
    token_id: str
    kind: HoneytokenType
    label: str
    canonical: str
    source: str                   # где обнаружен (лог/канал/путь)
    observed_at: datetime
    severity: Severity
    recommendations: Tuple[Recommendation, ...]
    meta: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------------------
# Генерация/подпись/проверка
# --------------------------------------------------------------------------------------

def _sign(tenant_id: str, kind: HoneytokenType, token_id: str, created_at: datetime) -> str:
    msg = f"{tenant_id}|{kind.value}|{token_id}|{int(created_at.timestamp())}".encode("utf-8")
    sig = hmac.new(_secret_bytes(), msg, hashlib.sha256).digest()[:10]
    return _b32(sig)

def _new_token_id() -> str:
    return _b32(secrets.token_bytes(10))

def _now() -> datetime:
    return datetime.now(timezone.utc)

def create_token(
    tenant_id: str,
    kind: HoneytokenType,
    label: str,
    expires_in_days: Optional[int] = 365,
    tags: Optional[Iterable[str]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Honeytoken:
    created = _now()
    token_id = _new_token_id()
    signature = _sign(tenant_id, kind, token_id, created)
    return Honeytoken(
        token_id=token_id,
        tenant_id=tenant_id,
        kind=kind,
        label=label,
        signature=signature,
        created_at=created,
        expires_at=(created + timedelta(days=expires_in_days)) if expires_in_days else None,
        tags=tuple(tags or ()),
        metadata=dict(metadata or {}),
    )

def rotate_token(src: Honeytoken, new_expires_in_days: Optional[int] = None) -> Honeytoken:
    """Создать новый токен на основе контекста старого (метки/теги переносятся), старый можно пометить revoked=True в вашем хранилище."""
    return create_token(
        tenant_id=src.tenant_id,
        kind=src.kind,
        label=src.label,
        expires_in_days=new_expires_in_days if new_expires_in_days is not None else (
            int(((src.expires_at - _now()).total_seconds() / 86400)) if src.expires_at else None
        ),
        tags=src.tags,
        metadata=src.metadata,
    )

def verify_canonical(token: str, tenant_id: Optional[str] = None, kind: Optional[HoneytokenType] = None) -> Optional[Tuple[str, str]]:
    """
    Проверяет канонический формат HTK1-<id>-<sig>.
    Возвращает (token_id, signature) при успехе.
    Если переданы tenant_id/kind — дополнительно сверяет HMAC.
    """
    m = re.fullmatch(r"HTK1-([A-Z2-7]{16})-([A-Z2-7]{16})", token)
    if not m:
        return None
    token_id, sig = m.group(1), m.group(2)
    if tenant_id and kind:
        # Поддерживаем «плавающий» created_at внутри +-7 дней для совместимости (временная устойчивость подписи)
        now = _now()
        for days_back in range(0, 8):
            try_time = now - timedelta(days=days_back)
            expected = _sign(tenant_id, kind, token_id, try_time)
            if hmac.compare_digest(expected, sig):
                return token_id, sig
        return None
    return token_id, sig


# --------------------------------------------------------------------------------------
# Генераторы артефактов (безопасные, но реалистичные)
# --------------------------------------------------------------------------------------

_RAND_ALPHANUM = string.ascii_letters + string.digits

def _rand(n: int) -> str:
    return "".join(secrets.choice(_RAND_ALPHANUM) for _ in range(n))

def _aws_key_id() -> str:
    # Формат похож на AKIAxxxxxxxxxxxxxx
    return "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))

def _aws_secret(fake_suffix: str) -> str:
    # 40 симв. base64-like + включённый канонический токен в комментарии
    core = "".join(secrets.choice(string.ascii_letters + string.digits + "/+") for _ in range(40))
    return f"{core} # {fake_suffix}"

def _github_token_prefix() -> str:
    return "ghp_"

def build_artifacts(ht: Honeytoken, base_url: str = "https://example.invalid/honey") -> GeneratedArtifacts:
    """
    Создаёт производные артефакты под размещение.
    base_url — домен вашего трекера (по умолчанию example.invalid — безопасный mock-домен).
    """
    canonical = ht.canonical()

    url = f"{base_url}/{canonical}?s={ht.signature}"
    aws = {
        "aws_access_key_id": _aws_key_id(),
        "aws_secret_access_key": _aws_secret(canonical),
        "aws_session_token": f"{_rand(64)}# {canonical}"
    }
    github = f"{_github_token_prefix()}{_rand(36)}{canonical}"

    env_text = (
        "# auto-generated decoy\n"
        f"APP_ENV=prod\n"
        f"DB_USER={_rand(10)}\n"
        f"DB_PASS={_rand(24)}\n"
        f"API_KEY={_rand(32)}\n"
        f"HONEYTOKEN={canonical}\n"
    )
    ini_text = (
        "[default]\n"
        f"aws_access_key_id={aws['aws_access_key_id']}\n"
        f"aws_secret_access_key={aws['aws_secret_access_key']}\n"
        f"# {canonical}\n"
    )
    db_conn = f"postgresql://{_rand(8)}:{_rand(16)}@db.internal.local:5432/app?sslmode=require&htk={canonical}"

    return GeneratedArtifacts(
        canonical=canonical,
        url=url,
        aws=aws,
        github=github,
        env_text=env_text,
        ini_text=ini_text,
        db_conn=db_conn,
    )


# --------------------------------------------------------------------------------------
# Сканирование/детекция в текстах и событиях
# --------------------------------------------------------------------------------------

# Поисковые шаблоны: ищем КАНОНИЧЕСКИЙ токен; любые «псевдо»-форматы несут его как комментарий/хвост.
RE_CANONICAL = re.compile(r"HTK1-[A-Z2-7]{16}-[A-Z2-7]{16}")
RE_URL = re.compile(r"https?://[^\s\"']+/(HTK1-[A-Z2-7]{16}-[A-Z2-7]{16})(?:\?[^ \t\r\n]*)?")
RE_GITHUB = re.compile(r"(gh[pousr]_[A-Za-z0-9]{20,})(HTK1-[A-Z2-7]{16}-[A-Z2-7]{16})")
RE_AWS = re.compile(r"AKIA[0-9A-Z]{16}.*?(HTK1-[A-Z2-7]{16}-[A-Z2-7]{16})", re.DOTALL)

def scan_text_for_tokens(text: str) -> List[str]:
    """Возвращает список уникальных канонических токенов, найденных в тексте."""
    found = set(RE_CANONICAL.findall(text))
    for rgx in (RE_URL, RE_GITHUB, RE_AWS):
        for m in rgx.findall(text):
            if isinstance(m, tuple):
                found.add(m[-1])
            else:
                found.add(m)
    return sorted(found)

def normalize_hit(
    canonical: str,
    source: str,
    observed_at: Optional[datetime],
    resolver: callable,
    extra_meta: Optional[Mapping[str, Any]] = None,
) -> Optional[HitEvent]:
    """
    Преобразует найденный канонический токен в нормализованное событие.
    resolver(canonical) -> Honeytoken | None — функция, возвращающая объект токена из хранилища.
    """
    ht = resolver(canonical)
    if not ht:
        return None
    # Базовая оценка серьёзности
    sev = Severity.MEDIUM
    recs: List[Recommendation] = [Recommendation.ALERT_ONLY]
    if ht.kind in (HoneytokenType.AWS_FAKE, HoneytokenType.GITHUB_FAKE, HoneytokenType.DB_CONN):
        sev = Severity.HIGH
        recs.append(Recommendation.ISOLATE_HOST)
    if ht.is_expired():
        # Снижаем; истёкший токен может жить в архивах
        sev = Severity.LOW
    if ht.revoked:
        sev = Severity.INFORMATIONAL

    return HitEvent(
        tenant_id=ht.tenant_id,
        token_id=ht.token_id,
        kind=ht.kind,
        label=ht.label,
        canonical=canonical,
        source=source,
        observed_at=observed_at or datetime.now(timezone.utc),
        severity=sev,
        recommendations=tuple(recs),
        meta={"tags": list(ht.tags), **(extra_meta or {})},
    )


# --------------------------------------------------------------------------------------
# Хранилище (in-memory пример) и резолвер
# --------------------------------------------------------------------------------------

class InMemoryStore:
    """Пример простого in-memory хранилища. В проде замените на DB/Redis."""
    def __init__(self) -> None:
        self._by_canonical: Dict[str, Honeytoken] = {}
        self._by_id: Dict[Tuple[str, str], Honeytoken] = {}  # (tenant_id, token_id)

    def add(self, ht: Honeytoken) -> None:
        self._by_canonical[ht.canonical()] = ht
        self._by_id[(ht.tenant_id, ht.token_id)] = ht

    def get_by_canonical(self, canonical: str) -> Optional[Honeytoken]:
        return self._by_canonical.get(canonical)

    def revoke(self, tenant_id: str, token_id: str) -> bool:
        ht = self._by_id.get((tenant_id, token_id))
        if not ht:
            return False
        ht.revoked = True
        return True


# --------------------------------------------------------------------------------------
# Утилиты размещения: генерация «decoy»-файлов
# --------------------------------------------------------------------------------------

def make_env_file(ht: Honeytoken) -> Tuple[str, str]:
    arts = build_artifacts(ht)
    name = f".env.{ht.token_id.lower()}"
    return name, arts.env_text or ""

def make_ini_file(ht: Honeytoken) -> Tuple[str, str]:
    arts = build_artifacts(ht)
    name = f"credentials-{ht.token_id.lower()}.ini"
    return name, arts.ini_text or ""

def make_db_conn(ht: Honeytoken) -> str:
    return build_artifacts(ht).db_conn or ""


# --------------------------------------------------------------------------------------
# Примеры интеграции / демонстрация (можно удалить/закрыть в продакшене)
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    # 1) Создание токенов
    store = InMemoryStore()
    t1 = create_token("acme", HoneytokenType.AWS_FAKE, "decoy aws key", expires_in_days=180, tags=("decoy",))
    t2 = create_token("acme", HoneytokenType.GITHUB_FAKE, "decoy github", expires_in_days=365)
    t3 = create_token("acme", HoneytokenType.DB_CONN, "decoy db", expires_in_days=None)

    for t in (t1, t2, t3):
        store.add(t)

    # 2) Генерация артефактов для размещения
    a1 = build_artifacts(t1)
    a2 = build_artifacts(t2)
    print("AWS decoy:", json.dumps(a1.aws, indent=2))
    print("GitHub decoy:", a2.github[:60] + "...")

    # 3) Сканирование текста
    sample = f"""
    Push credentials:
    {a1.ini_text}

    hardcoded token: {a2.github}

    visit: {a1.url}
    """
    found = scan_text_for_tokens(sample)
    print("Found tokens:", found)

    # 4) Нормализация событий (resolver из хранилища)
    def _resolver(canon: str) -> Optional[Honeytoken]:
        return store.get_by_canonical(canon)

    for tok in found:
        evt = normalize_hit(tok, source="repo:infra/ops", observed_at=None, resolver=_resolver, extra_meta={"repo": "infra/ops"})
        print(json.dumps(asdict(evt), default=str, ensure_ascii=False, indent=2))
