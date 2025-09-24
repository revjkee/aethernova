# -*- coding: utf-8 -*-
"""
policy-core / examples / quickstart / run.py

Промышленный Quickstart:
- FastAPI-приложение.
- Подключение PAP Admin API (/v1/pap/*).
- Демонстрационный PDP (/v1/pdp/authorize) с простым ABAC-матчингом.
- Исполнение obligations: действие "redact" для полезной нагрузки.
- Метрики (/metrics) через policy_core.observability.metrics.
- Health-пробы: /_/healthz, /_/readyz.
- Сидирование примерной политики при старте.

Запуск:
    python -m examples.quickstart.run
или:
    uvicorn examples.quickstart.run:app --host 0.0.0.0 --port 8080

Зависимости: fastapi, pydantic, (опц.) prometheus_client, uvicorn.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# --- Импорт из policy_core ---
# PAP Admin API (префикс /v1/pap)
from policy_core.pap.admin_api import (
    router as pap_router,
    PolicyIn,
    PolicyUpdate,
    Rule,
    PolicyService,
    get_service as get_policy_service_singleton,
)

# Обязательства: redact
from policy_core.obligations.actions.redact import apply_obligation

# Метрики
from policy_core.observability.metrics import get_metrics


# --------------------------------------------------------------------------------------
# ЛОГИРОВАНИЕ
# --------------------------------------------------------------------------------------

logger = logging.getLogger("policy_core.examples.quickstart")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)


# --------------------------------------------------------------------------------------
# Pydantic-модели для PDP
# --------------------------------------------------------------------------------------

class Subject(BaseModel):
    # Произвольные атрибуты субъекта (ABAC). Примеры: {"role":"analyst","department":"risk"}
    attrs: Dict[str, Any] = Field(default_factory=dict)


class Resource(BaseModel):
    # Произвольные атрибуты ресурса. Примеры: {"type":"payment","country":"SE"}
    attrs: Dict[str, Any] = Field(default_factory=dict)


class PDPRequest(BaseModel):
    subject: Subject = Field(default_factory=Subject)
    action: str = Field(..., min_length=1)
    resource: Resource = Field(default_factory=Resource)
    # Контекст запроса (опционально): {"tenant":"acme","correlation_id":"..."}
    context: Dict[str, Any] = Field(default_factory=dict)
    # Данные для потенциальной редакции obligations (любой JSON)
    payload: Any = None


class PDPDecision(BaseModel):
    decision: str  # "Permit" | "Deny" | "NotApplicable"
    policy_id: Optional[str] = None
    obligations: List[Dict[str, Any]] = Field(default_factory=list)
    payload: Any = None  # редактированный payload, если применялось редактирование


# --------------------------------------------------------------------------------------
# УТИЛИТЫ МАТЧИНГА ABAC
# --------------------------------------------------------------------------------------

def _match_condition(condition: Optional[Dict[str, Any]], subject: Dict[str, Any], resource: Dict[str, Any]) -> bool:
    """
    Очень простой матчер условий:
      - поддерживает равенство по плоскому словарю: {"subject.role":"analyst","resource.type":"payment"}
      - поддерживает regex: {"subject.department": {"regex": "^risk|fraud$"}}
      - если condition == None -> True
    """
    if not condition:
        return True
    for key, expected in condition.items():
        if key.startswith("subject."):
            val = subject.get(key.split(".", 1)[1])
        elif key.startswith("resource."):
            val = resource.get(key.split(".", 1)[1])
        else:
            # свободный ключ — ищем в subject, затем в resource
            val = subject.get(key, resource.get(key))
        if isinstance(expected, dict) and "regex" in expected:
            pattern = expected["regex"]
            if not isinstance(val, str) or not re.fullmatch(pattern, val):
                return False
        else:
            if val != expected:
                return False
    return True


def _rule_matches(rule: Rule, action: str, subject: Dict[str, Any], resource: Dict[str, Any]) -> bool:
    if rule.action != action:
        return False
    # Простая проверка по resource: строковое равенство или шаблон "*"
    if rule.resource not in ("*", resource.get("type"), resource.get("id"), resource.get("name")):
        # допускаем точное совпадение по произвольному атрибуту "type"
        if rule.resource != resource.get("type"):
            return False
    # Условия (ABAC):
    return _match_condition(getattr(rule, "condition", None), subject, resource)


# --------------------------------------------------------------------------------------
# PDP-СЕРВИС
# --------------------------------------------------------------------------------------

@dataclass
class PDPResult:
    decision: str
    policy_id: Optional[str]
    obligations: List[Dict[str, Any]]


class PDPService:
    """
    Демонстрационный PDP: последовательно проверяет политики (published, по приоритету).
    Эффекты:
      - первая совпавшая с effect=deny -> "Deny"
      - первая совпавшая с effect=allow -> "Permit"
      - иначе "NotApplicable"
    Пример obligation (возвращаем вместе с решением):
      {
        "type": "redact",
        "policy_id": "...",
        "obligation_id": "obl-1",
        "config": {...},     # RedactConfig в виде dict (см. redact.apply_obligation)
        "context": {"actor":"pdp","reason":"gdpr.art32"}
      }
    """
    def __init__(self, policy_service: PolicyService) -> None:
        self.policies = policy_service
        self.metrics = get_metrics()

    async def evaluate(self, req: PDPRequest) -> PDPResult:
        # Получаем опубликованные политики (в порядке приоритета desc)
        items, _ = await self.policies.list(q=None, status="published", tag=None, sort="priority:desc", limit=1000, offset=0)
        subject = req.subject.attrs or {}
        resource = req.resource.attrs or {}

        for p in items:
            # Политика может содержать несколько правил — ищем первое совпадение
            for r in p.rules:
                if _rule_matches(r, req.action, subject, resource):
                    effect = r.effect
                    decision = "Permit" if effect == "allow" else "Deny"
                    # Демо: если в тегах есть "ob.redact", вернем obligation redact
                    obligations: List[Dict[str, Any]] = []
                    if "ob.redact" in (p.tags or []):
                        obligations.append(_demo_redact_obligation(p.id))
                    self.metrics.pdp_decision(decision, effect, tenant=req.context.get("tenant"), policy_id=str(p.id))
                    return PDPResult(decision=decision, policy_id=str(p.id), obligations=obligations)

        self.metrics.pdp_decision("NotApplicable", "none", tenant=req.context.get("tenant"), policy_id=None)
        return PDPResult(decision="NotApplicable", policy_id=None, obligations=[])


def _demo_redact_obligation(policy_id: str) -> Dict[str, Any]:
    """
    Демонстрационная obligation конфигурация "redact":
    - маскируем user.email, users[*].email, payment.card (оставляя последние 4).
    - включаем детекторы email/phone/cc по всему payload.
    """
    return {
        "type": "redact",
        "policy_id": policy_id,
        "obligation_id": "obl-redact-1",
        "config": {
            "selectors": [
                {"type": "glob", "value": "user.email"},
                {"type": "glob", "value": "users[*].email"},
                {"type": "pointer", "value": "/payment/card"},
            ],
            "strategy": {
                "strategy": "mask",
                "keep_last4": True,
                "mask_char": "*",
            },
            "detectors": {
                "email": True,
                "phone": True,
                "cc": True,
                "iban": False,
                "custom_patterns": ["(?i)bearer\\s+[a-z0-9._\\-]+"],
            },
            "max_depth": 40,
            "max_nodes": 200000,
            "max_output_bytes": 10485760,
            "on_no_match": "ok",
        },
        "context": {"actor": "pdp", "reason": "gdpr.art32"},
    }


# --------------------------------------------------------------------------------------
# FASTAPI ПРИЛОЖЕНИЕ
# --------------------------------------------------------------------------------------

app = FastAPI(title="policy-core quickstart", version="1.0.0")

# Метрики и health
_metrics = get_metrics()
_metrics.instrument_fastapi(app, path="/metrics", skip_paths={"/_/healthz", "/_/readyz"})

@app.get("/_/healthz")
async def healthz():
    return {"status": "ok"}

@app.get("/_/readyz")
async def readyz():
    return {"status": "ready"}

# PAP Admin API (CRUD политик и т.д.)
app.include_router(pap_router)


# --------------------------------------------------------------------------------------
# PDP ЭНДПОИНТ
# --------------------------------------------------------------------------------------

# Синглтон PolicyService из PAP (общий репозиторий)
async def _get_policy_service() -> PolicyService:
    return await get_policy_service_singleton()

# PDP сервис (инициализируем при первом запросе)
_pdp_service: Optional[PDPService] = None

async def _get_pdp_service() -> PDPService:
    global _pdp_service
    if _pdp_service is None:
        svc = await _get_policy_service()
        _pdp_service = PDPService(svc)
    return _pdp_service


@app.post("/v1/pdp/authorize", response_model=PDPDecision, summary="ABAC PDP: принять решение и выполнить obligations")
async def pdp_authorize(req: PDPRequest):
    pdp = await _get_pdp_service()

    # Оценка
    result = await pdp.evaluate(req)

    # Применение obligations к payload (только для демонстрации)
    payload = req.payload
    for obl in result.obligations:
        if obl.get("type") == "redact" and payload is not None:
            try:
                payload, events = apply_obligation(payload, obl)
                _metrics.obligation_applied("redact", status="ok", tenant=req.context.get("tenant"))
                logger.info("obligation.redact applied: %s", json.dumps(events, ensure_ascii=False))
            except Exception as e:
                _metrics.obligation_applied("redact", status="error", tenant=req.context.get("tenant"))
                raise HTTPException(status_code=500, detail=f"obligation.redact failed: {e}")

    return PDPDecision(
        decision=result.decision,
        policy_id=result.policy_id,
        obligations=result.obligations,
        payload=payload,
    )


# --------------------------------------------------------------------------------------
# СИДИРОВАНИЕ ПОЛИТИКИ ПРИ СТАРТЕ
# --------------------------------------------------------------------------------------

@app.on_event("startup")
async def _seed_policy():
    svc = await _get_policy_service()
    # проверим, есть ли уже демо-политика
    items, _ = await svc.list(q="demo-quickstart", status=None, tag=None, sort="created_at:desc", limit=1, offset=0)
    if items:
        logger.info("demo policy already present: %s", items[0].name)
        return

    demo = PolicyIn(
        name="demo-quickstart",
        description="Demo policy: allow read on resource type 'payment' for subject.role=='analyst'; add redact obligation via tag.",
        rules=[
            Rule(
                action="read",
                resource="payment",
                subject={"role": "analyst"},
                condition={"subject.role": "analyst"},
                effect="allow",
            ),
            Rule(
                action="read",
                resource="payment",
                subject={"role": "guest"},
                condition={"subject.role": {"regex": "^guest$"}},
                effect="deny",
            ),
        ],
        priority=1000,
        tags=["demo", "ob.redact"],
        status="published",
    )
    created = await svc.create(demo, principal=type("P", (), {"sub": "bootstrap", "roles": ["policy.admin"]})(), idempotency_key="qs-demo-1")
    logger.info("seeded policy: id=%s name=%s", created.id, created.name)


# --------------------------------------------------------------------------------------
# ТОЧКА ВХОДА
# --------------------------------------------------------------------------------------

def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v else default


if __name__ == "__main__":
    host = _env("QS_HOST", "0.0.0.0")
    port = int(_env("QS_PORT", "8080"))
    reload_ = os.getenv("QS_RELOAD", "false").lower() in ("1", "true", "yes", "on")

    try:
        import uvicorn  # type: ignore
    except Exception as e:
        logger.error("uvicorn is required to run this example: pip install uvicorn[standard]; error: %s", e)
        sys.exit(1)

    logger.info("Starting policy-core quickstart on %s:%s", host, port)
    uvicorn.run("examples.quickstart.run:app", host=host, port=port, reload=reload_, factory=False, log_level="info")
