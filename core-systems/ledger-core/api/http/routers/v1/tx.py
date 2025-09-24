# -*- coding: utf-8 -*-
"""
ledger-core/api/http/routers/v1/tx.py

Промышленный роутер управления транзакциями:
- POST /transactions: создание с Idempotency-Key
- GET  /transactions/{tx_id}: чтение с ETag/If-None-Match
- GET  /transactions: листинг с курсорной пагинацией и фильтрами
- POST /transactions/{tx_id}/approve|hold|release|refund: операции статусов

Зависимости:
- FastAPI/Starlette, Pydantic v1/v2 совместимо (используем базовые поля/валидаторы)
- AuthMiddleware помещает Principal в request.scope["auth.principal"] (см. ваш middleware)
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field, conint, conlist, validator

# Ключи scope от вашего middleware
AUTH_SCOPE_KEY = "auth.principal"
REQUEST_ID_SCOPE_KEY = "request.id"

router = APIRouter(prefix="/v1/tx", tags=["transactions"])


# ============================ Модель аутентифицированного субъекта ============================

class Principal(BaseModel):
    subject: str
    roles: Tuple[str, ...] = ()
    scopes: Tuple[str, ...] = ()
    method: str = "jwt"

def _require_roles(principal: Principal, allowed_roles: Iterable[str]) -> None:
    if not set(principal.roles).intersection(allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_problem("forbidden", "Insufficient role", {"required_roles": list(allowed_roles)}),
        )


# ============================ DTO: вход/выход ============================

class Currency(str, Enum):
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    BRL = "BRL"
    # расширяйте при необходимости

class TxStatus(str, Enum):
    initiated = "initiated"
    pending = "pending"
    approved = "approved"
    held = "held"
    released = "released"
    refunded = "refunded"
    failed = "failed"
    completed = "completed"

class TxCreateIn(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=64)
    amount: int = Field(..., ge=1)  # в минимальных единицах (центы)
    currency: Currency
    description: Optional[str] = Field(None, max_length=512)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class TxOut(BaseModel):
    id: str
    account_id: str
    amount: int
    currency: Currency
    status: TxStatus
    created_at: datetime
    updated_at: datetime
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # сервис может включить дополнительные поля (например, balance_after)
    class Config:
        orm_mode = True

class TxActionOut(BaseModel):
    id: str
    status: TxStatus
    updated_at: datetime

class TxListOut(BaseModel):
    items: List[TxOut]
    next_cursor: Optional[str] = None
    limit: int

class SortField(str, Enum):
    created_at = "created_at"
    amount = "amount"

class SortOrder(str, Enum):
    asc = "asc"
    desc = "desc"

# ============================ Протокол сервисного слоя ============================

class TxService(Protocol):
    async def create_transaction(
        self,
        *,
        principal: Principal,
        idem_key: Optional[str],
        data: TxCreateIn,
        request_id: str,
    ) -> Tuple[TxOut, bool]:
        """
        Возвращает (tx, reused), где reused=True если идемпотентный ключ совпал с уже созданной операцией.
        Может выбросить HTTPException(409) при конфликте параметров под тем же ключом.
        """

    async def get_transaction(self, *, principal: Principal, tx_id: str) -> TxOut:
        ...

    async def list_transactions(
        self,
        *,
        principal: Principal,
        account_id: Optional[str],
        statuses: Optional[List[TxStatus]],
        created_from: Optional[datetime],
        created_to: Optional[datetime],
        min_amount: Optional[int],
        max_amount: Optional[int],
        cursor: Optional[str],
        limit: int,
        sort_field: SortField,
        sort_order: SortOrder,
    ) -> TxListOut:
        ...

    async def approve(self, *, principal: Principal, tx_id: str) -> TxActionOut:
        ...

    async def hold(self, *, principal: Principal, tx_id: str) -> TxActionOut:
        ...

    async def release(self, *, principal: Principal, tx_id: str) -> TxActionOut:
        ...

    async def refund(self, *, principal: Principal, tx_id: str) -> TxActionOut:
        ...


# ============================ DI-зависимости (подменяются в приложении) ============================

async def get_principal(request: Request) -> Principal:
    p = request.scope.get(AUTH_SCOPE_KEY)
    if not p:
        # Ваш AuthMiddleware возвращает 401/403, сюда попадём только при ошибочной конфигурации
        raise HTTPException(status_code=401, detail=_problem("unauthorized", "Authentication required"))
    if isinstance(p, Principal):
        return p
    # Если middleware передал dataclass/словарь — нормализуем
    return Principal.parse_obj(getattr(p, "__dict__", p))

def _problem(code: str, title: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    d = {"type": f"https://problems.ledger/{code}", "title": title, "code": code}
    if extra:
        d.update(extra)
    return d

# В реальном приложении зарегистрируйте провайдер сервиса через Depends
# Здесь — заглушка, которую вы переопределите в старте приложения.
async def get_tx_service() -> TxService:
    raise HTTPException(
        status_code=500,
        detail=_problem("server_error", "TxService is not bound in dependency injection container"),
    )


# ============================ Вспомогательные функции ============================

def _etag_for(tx: TxOut) -> str:
    # Детерминированный ETag на основе id + updated_at наносекунд и статуса
    base = f"{tx.id}:{int(tx.updated_at.timestamp()*1e9)}:{tx.status}"
    return '"' + hashlib.sha256(base.encode("utf-8")).hexdigest()[:32] + '"'

def _check_idempotency_key(idem_key: Optional[str]) -> Optional[str]:
    if idem_key is None:
        return None
    idem_key = idem_key.strip()
    if not (8 <= len(idem_key) <= 128):
        raise HTTPException(status_code=400, detail=_problem("invalid_request", "Invalid Idempotency-Key length"))
    return idem_key

# ============================ Роуты ============================

@router.post(
    "/transactions",
    status_code=status.HTTP_201_CREATED,
    response_model=TxOut,
    responses={
        201: {"description": "Создано"},
        200: {"description": "Повтор идемпотентного запроса — возвращаем существующую транзакцию"},
        400: {"description": "Неверный запрос"},
        401: {"description": "Неавторизовано"},
        403: {"description": "Недостаточно прав"},
        409: {"description": "Конфликт идемпотентности/параметров"},
    },
)
async def create_transaction(
    request: Request,
    payload: TxCreateIn,
    response: Response,
    principal: Principal = Depends(get_principal),
    service: TxService = Depends(get_tx_service),
    idempotency_key: Optional[str] = Header(default=None, convert_underscores=False, alias="Idempotency-Key"),
):
    # RBAC: создавать транзакции разрешено writer/finops
    _require_roles(principal, {"role-writer", "role-finops"})

    idem_key = _check_idempotency_key(idempotency_key)
    request_id = str(request.scope.get(REQUEST_ID_SCOPE_KEY) or "unknown")

    tx, reused = await service.create_transaction(
        principal=principal, idem_key=idem_key, data=payload, request_id=request_id
    )

    # Идемпотентные повторные запросы — 200 OK, иначе 201 Created
    response.status_code = status.HTTP_200_OK if reused else status.HTTP_201_CREATED
    response.headers["ETag"] = _etag_for(tx)
    if idem_key:
        response.headers["Idempotency-Key"] = idem_key
    return tx


@router.get(
    "/transactions/{tx_id}",
    response_model=TxOut,
    responses={
        200: {"description": "OK"},
        304: {"description": "Не изменилось (If-None-Match)"},
        401: {"description": "Неавторизовано"},
        403: {"description": "Недостаточно прав"},
        404: {"description": "Не найдено"},
        412: {"description": "Предусловие не выполнено (If-Match)"},
    },
)
async def get_transaction(
    tx_id: str,
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal),
    service: TxService = Depends(get_tx_service),
    if_none_match: Optional[str] = Header(default=None, convert_underscores=False, alias="If-None-Match"),
    if_match: Optional[str] = Header(default=None, convert_underscores=False, alias="If-Match"),
):
    # RBAC: чтение доступно всем с ролью reader (или шире)
    _require_roles(principal, {"role-reader", "role-writer", "role-finops", "role-support-l1", "role-support-l2", "role-compliance", "role-sre", "role-admin"})

    tx = await service.get_transaction(principal=principal, tx_id=tx_id)
    etag = _etag_for(tx)

    # If-Match предикат (оптимистическая блокировка клиента)
    if if_match is not None and if_match.strip() != etag:
        raise HTTPException(status_code=412, detail=_problem("precondition_failed", "ETag mismatch"))

    # If-None-Match (клиентский кеш)
    if if_none_match is not None and if_none_match.strip() == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    response.headers["ETag"] = etag
    return tx


@router.get(
    "/transactions",
    response_model=TxListOut,
    responses={
        200: {"description": "OK"},
        401: {"description": "Неавторизовано"},
        403: {"description": "Недостаточно прав"},
    },
)
async def list_transactions(
    principal: Principal = Depends(get_principal),
    service: TxService = Depends(get_tx_service),
    # Фильтры
    account_id: Optional[str] = Query(default=None, min_length=1, max_length=64),
    statuses: Optional[List[TxStatus]] = Query(default=None),
    created_from: Optional[datetime] = Query(default=None),
    created_to: Optional[datetime] = Query(default=None),
    min_amount: Optional[int] = Query(default=None, ge=1),
    max_amount: Optional[int] = Query(default=None, ge=1),
    # Пагинация курсором
    cursor: Optional[str] = Query(default=None, max_length=256),
    limit: conint(ge=1, le=500) = Query(default=100, description="Количество элементов на страницу (1..500)"),
    # Сортировка
    sort_field: SortField = Query(default=SortField.created_at),
    sort_order: SortOrder = Query(default=SortOrder.desc),
):
    _require_roles(principal, {"role-reader", "role-writer", "role-finops", "role-support-l1", "role-support-l2", "role-compliance", "role-admin", "role-sre"})

    # Нормализация диапазонов
    if created_from and created_to and created_from > created_to:
        raise HTTPException(status_code=400, detail=_problem("invalid_request", "created_from > created_to"))

    if min_amount and max_amount and min_amount > max_amount:
        raise HTTPException(status_code=400, detail=_problem("invalid_request", "min_amount > max_amount"))

    return await service.list_transactions(
        principal=principal,
        account_id=account_id,
        statuses=statuses,
        created_from=created_from,
        created_to=created_to,
        min_amount=min_amount,
        max_amount=max_amount,
        cursor=cursor,
        limit=int(limit),
        sort_field=sort_field,
        sort_order=sort_order,
    )


# ====== Операции над статусом (требуют усиленных ролей) ======

@router.post(
    "/transactions/{tx_id}/approve",
    response_model=TxActionOut,
    status_code=status.HTTP_200_OK,
    responses={403: {"description": "Недостаточно прав"}, 404: {"description": "Не найдено"}},
)
async def approve_transaction(
    tx_id: str,
    principal: Principal = Depends(get_principal),
    service: TxService = Depends(get_tx_service),
):
    _require_roles(principal, {"role-approver", "role-finops", "role-compliance"})
    return await service.approve(principal=principal, tx_id=tx_id)


@router.post(
    "/transactions/{tx_id}/hold",
    response_model=TxActionOut,
    status_code=status.HTTP_200_OK,
)
async def hold_transaction(
    tx_id: str,
    principal: Principal = Depends(get_principal),
    service: TxService = Depends(get_tx_service),
):
    _require_roles(principal, {"role-support-l2", "role-compliance", "role-finops"})
    return await service.hold(principal=principal, tx_id=tx_id)


@router.post(
    "/transactions/{tx_id}/release",
    response_model=TxActionOut,
    status_code=status.HTTP_200_OK,
)
async def release_transaction(
    tx_id: str,
    principal: Principal = Depends(get_principal),
    service: TxService = Depends(get_tx_service),
):
    _require_roles(principal, {"role-support-l2", "role-compliance", "role-finops"})
    return await service.release(principal=principal, tx_id=tx_id)


@router.post(
    "/transactions/{tx_id}/refund",
    response_model=TxActionOut,
    status_code=status.HTTP_200_OK,
)
async def refund_transaction(
    tx_id: str,
    principal: Principal = Depends(get_principal),
    service: TxService = Depends(get_tx_service),
):
    _require_roles(principal, {"role-finops", "role-approver"})
    return await service.refund(principal=principal, tx_id=tx_id)
