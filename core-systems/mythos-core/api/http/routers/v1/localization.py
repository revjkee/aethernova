# mythos-core/api/http/routers/v1/localization.py
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, Response, status
from pydantic import BaseModel, Field, conint, constr, validator

# Требует ваш middleware с декоратором/типами
# from mythos_core.api.http.middleware.auth import require_scopes, Principal
try:
    from ...middleware.auth import require_scopes, Principal  # типичный относительный путь
except Exception:  # pragma: no cover - на случай прямого запуска модуля
    def require_scopes(*args, **kwargs):  # заглушка на dev
        def deco(fn):
            return fn
        return deco
    class Principal:  # заглушка на dev
        roles: set = set()
        scopes: set = set()


logger = logging.getLogger("mythos.localization")

localization_router = APIRouter(prefix="/v1/localization", tags=["localization"])


# -----------------------------
# Модели (согласованы с protobuf схемой mythos.v1.localization)
# -----------------------------

class TextFormat(str, Enum):
    TEXT_FORMAT_UNSPECIFIED = "unspecified"
    TEXT_FORMAT_PLAIN = "plain"
    TEXT_FORMAT_ICU = "icu"
    TEXT_FORMAT_MARKDOWN = "markdown"
    TEXT_FORMAT_HTML = "html"


class PluralCategory(str, Enum):
    ZERO = "zero"
    ONE = "one"
    TWO = "two"
    FEW = "few"
    MANY = "many"
    OTHER = "other"


class Gender(str, Enum):
    NEUTER = "neuter"
    MASCULINE = "masculine"
    FEMININE = "feminine"
    OTHER = "other"


BCP47 = constr(regex=r"^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$")


class ValueResponse(BaseModel):
    format: TextFormat = Field(TextFormat.TEXT_FORMAT_PLAIN, description="Формат строки")
    text: str = Field(..., description="Итоговый текст")
    effective_locale: BCP47 = Field(..., description="Фактически использованная локаль после фолбэков")
    plural_category: Optional[PluralCategory] = None
    gender: Optional[Gender] = None
    context: Optional[str] = None
    revision_id: Optional[str] = None
    checksum_sha256: Optional[str] = Field(
        None, description="HEX SHA-256 контента (если доступен)"
    )


class Placeholder(BaseModel):
    name: str
    type: str
    example: Optional[str] = None
    required: bool = False


class Variant(BaseModel):
    # Для простоты HTTP возвращаем уже выбранный вариант, без всех селекторов
    format: TextFormat = TextFormat.TEXT_FORMAT_PLAIN
    text: str


class LocalizedValue(BaseModel):
    locale: BCP47
    variant: Variant
    placeholders: List[Placeholder] = Field(default_factory=list)
    status: Optional[str] = None
    max_length: Optional[int] = None
    allow_html: Optional[bool] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    checksum_sha256: Optional[str] = None


class LocalizedString(BaseModel):
    key: str
    domain: Optional[str] = None
    description: Optional[str] = None
    source_locale: Optional[BCP47] = None
    source_text: Optional[str] = None
    value: Optional[LocalizedValue] = None


class BundleResponse(BaseModel):
    namespace: str
    version: Optional[str] = None
    revision_id: Optional[str] = None
    entries: List[LocalizedString]
    tags: Dict[str, str] = Field(default_factory=dict)
    next_cursor: Optional[str] = Field(None, description="Курсор для следующей страницы, если есть")


class Problem(BaseModel):
    type: str
    title: str
    status: int
    code: str
    detail: Optional[str] = None


# -----------------------------
# Cursor/ETag утилиты
# -----------------------------

def _make_cursor(offset: int) -> str:
    payload = json.dumps({"o": int(offset)}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _parse_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        return int(data.get("o", 0))
    except Exception:
        return 0


def _hash_etag(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
        h.update(b"\x1f")
    return f'W/"{h.hexdigest()}"'


# -----------------------------
# Репозиторий (интерфейс) и dev-реализация
# -----------------------------

class LocalizationRepo(Protocol):
    async def fetch_bundle(
        self,
        namespace: str,
        locale: Optional[str],
        keys: Optional[Sequence[str]],
        since_revision_id: Optional[str],
        include_fallbacks: bool,
        limit: int,
        offset: int,
    ) -> Tuple[BundleResponse, int]:
        """
        Возвращает BundleResponse и общее число элементов (для вычисления next_cursor).
        entries должны содержать уже отфильтрованные/подобранные по locale значения.
        """

    async def resolve_value(
        self,
        key: str,
        locale: str,
        fallback_chain: Optional[Sequence[str]],
        plural_number: Optional[float],
        gender: Optional[Gender],
        context: Optional[str],
    ) -> ValueResponse:
        """
        Возвращает итоговую строку (с учётом фолбэков/вариантов) и метаданные.
        """


@dataclass
class _Entry:
    key: str
    domain: str
    values: Dict[str, str]  # locale -> text
    revision_id: str


class InMemoryLocalizationRepo(LocalizationRepo):
    """
    Безопасный dev-бэкенд: хранит минимум данных, но полноценно обслуживает запросы.
    В проде подменяется на реализацию поверх БД/kv/TMS.
    """

    def __init__(self) -> None:
        # Пример: одна строка для демонстрации
        self._entries: List[_Entry] = [
            _Entry(
                key="ui.menu.play_button",
                domain="ui",
                values={"en": "Play", "ru": "Играть"},
                revision_id="rev-0001",
            )
        ]
        self._bundle_version = "1.0.0"
        self._bundle_revision = "rev-0001"
        self._namespace_tags = {"env": "dev"}

    async def fetch_bundle(
        self,
        namespace: str,
        locale: Optional[str],
        keys: Optional[Sequence[str]],
        since_revision_id: Optional[str],
        include_fallbacks: bool,
        limit: int,
        offset: int,
    ) -> Tuple[BundleResponse, int]:
        # Фильтрация по ключам
        pool = self._entries
        if keys:
            ks = set(keys)
            pool = [e for e in self._entries if e.key in ks]
        total = len(pool)
        slice_ = pool[offset : offset + limit]

        loc = (locale or "en").lower()
        entries: List[LocalizedString] = []
        for e in slice_:
            text = e.values.get(loc) or e.values.get("en") or ""
            entries.append(
                LocalizedString(
                    key=e.key,
                    domain=e.domain,
                    value=LocalizedValue(
                        locale=loc,
                        variant=Variant(format=TextFormat.TEXT_FORMAT_PLAIN, text=text),
                        checksum_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    ),
                )
            )

        bundle = BundleResponse(
            namespace=namespace,
            version=self._bundle_version,
            revision_id=self._bundle_revision,
            entries=entries,
            tags=self._namespace_tags,
            next_cursor=None,  # заполним в роутере, исходя из total/offset/limit
        )
        return bundle, total

    async def resolve_value(
        self,
        key: str,
        locale: str,
        fallback_chain: Optional[Sequence[str]],
        plural_number: Optional[float],
        gender: Optional[Gender],
        context: Optional[str],
    ) -> ValueResponse:
        # На dev просто ищем точное соответствие, затем en как fallback
        loc = (locale or "en").lower()
        entry = next((e for e in self._entries if e.key == key), None)
        if not entry:
            raise HTTPException(status_code=404, detail="Key not found")
        text = entry.values.get(loc) or entry.values.get("en")
        if text is None:
            raise HTTPException(status_code=404, detail="No value for given locale")

        return ValueResponse(
            format=TextFormat.TEXT_FORMAT_PLAIN,
            text=text,
            effective_locale=loc,
            plural_category=None,
            gender=gender,
            context=context,
            revision_id=entry.revision_id,
            checksum_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )


# -----------------------------
# DI: получение репозитория
# -----------------------------

# В проде в приложении можно сделать: app.dependency_overrides[get_repo] = lambda: ProdRepo(...)
async def get_repo() -> LocalizationRepo:
    return InMemoryLocalizationRepo()


# -----------------------------
# Эндпоинты
# -----------------------------

@localization_router.get(
    "/bundles/{namespace}",
    response_model=BundleResponse,
    responses={
        401: {"model": Problem},
        403: {"model": Problem},
        404: {"model": Problem},
        412: {"model": Problem},
    },
    summary="Получить бандл локализации",
)
@require_scopes("read:localization")
async def get_bundle(
    request: Request,
    response: Response,
    namespace: constr(regex=r"^[a-zA-Z0-9_\-\.]{1,64}$) = Path(..., description="Пространство имён бандла"),
    locale: Optional[BCP47] = Query(None, description="Желаемая локаль для фильтрации"),
    keys: Optional[List[str]] = Query(None, description="Фильтр по ключам (повторяющийся параметр keys=...)"),
    since_revision_id: Optional[str] = Query(None, description="Вернуть только строки после данной ревизии (если поддерживается бэкендом)"),
    include_fallbacks: bool = Query(False, description="Включать ли fallback-цепочку при фильтрации"),
    limit: conint(ge=1, le=500) = Query(100, description="Размер страницы"),
    cursor: Optional[str] = Query(None, description="Курсор постраничного чтения"),
    if_none_match: Optional[str] = Header(None, convert_underscores=False),
    repo: LocalizationRepo = Depends(get_repo),
):
    """
    Возвращает страницу бандла. Поддерживает ETag/If-None-Match и cursor-пагинацию.
    """
    offset = _parse_cursor(cursor)
    bundle, total = await repo.fetch_bundle(
        namespace=namespace,
        locale=locale,
        keys=keys,
        since_revision_id=since_revision_id,
        include_fallbacks=include_fallbacks,
        limit=limit,
        offset=offset,
    )

    # Вычисляем next_cursor
    new_offset = offset + len(bundle.entries)
    next_cursor = _make_cursor(new_offset) if new_offset < total else None
    bundle.next_cursor = next_cursor

    # ETag на основе ревизии и параметров запроса (стабильно)
    etag = _hash_etag(
        "bundle",
        namespace,
        bundle.revision_id or "",
        locale or "",
        ",".join(sorted(keys or [])),
        since_revision_id or "",
        str(limit),
        str(offset),
    )
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "public, max-age=60"
    response.headers["Vary"] = "Accept-Encoding"

    if if_none_match and if_none_match == etag:
        # Пустой ответ, но с теми же заголовками
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return None

    return bundle


@localization_router.get(
    "/value",
    response_model=ValueResponse,
    responses={
        400: {"model": Problem},
        401: {"model": Problem},
        403: {"model": Problem},
        404: {"model": Problem},
    },
    summary="Получить локализованное значение по ключу",
)
@require_scopes("read:localization")
async def get_value(
    response: Response,
    key: constr(min_length=1, max_length=256) = Query(..., description="Полный ключ строки (dot.notation)"),
    locale: BCP47 = Query(..., description="Желаемая локаль BCP-47"),
    fallback_chain: Optional[List[BCP47]] = Query(None, description="Явная цепочка фолбэков"),
    plural_number: Optional[float] = Query(None, description="Число для плурализации"),
    gender: Optional[Gender] = Query(None, description="Гендер для выбора варианта"),
    context: Optional[str] = Query(None, description="Контекст для выбора варианта"),
    if_none_match: Optional[str] = Header(None, convert_underscores=False),
    repo: LocalizationRepo = Depends(get_repo),
):
    """
    Возвращает итоговую строку и метаданные. Кэшируется 60с, поддерживает ETag.
    """
    val = await repo.resolve_value(
        key=key,
        locale=locale,
        fallback_chain=fallback_chain,
        plural_number=plural_number,
        gender=gender,
        context=context,
    )

    # ETag на основе ревизии/контента и входных параметров
    etag = _hash_etag(
        "value",
        key,
        locale,
        ",".join(fallback_chain or []),
        str(plural_number or ""),
        (gender or ""),
        (context or ""),
        (val.revision_id or ""),
        (val.checksum_sha256 or ""),
    )
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "public, max-age=60"
    response.headers["Vary"] = "Accept-Encoding"

    if if_none_match and if_none_match == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return None

    return val


# -----------------------------
# Пример подключения в приложении:
#
# from fastapi import FastAPI
# from mythos_core.api.http.routers.v1.localization import localization_router
#
# app = FastAPI()
# app.include_router(localization_router)
#
# В проде подмените зависимость:
# app.dependency_overrides[get_repo] = lambda: ProdLocalizationRepo(...)
# -----------------------------
