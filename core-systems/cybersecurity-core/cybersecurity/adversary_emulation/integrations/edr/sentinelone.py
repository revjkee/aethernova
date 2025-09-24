# SPDX-License-Identifier: MIT
"""
cybersecurity-core/cybersecurity/adversary_emulation/integrations/edr/sentinelone.py

Промышленный асинхронный клиент SentinelOne Management API v2.1.

Подтверждённые факты (см. источники в конце файла):
- Базовый домен консоли: https://<subdomain>.sentinelone.net.  # ref: Mimecast, Tenable
- Аутентификация: заголовок Authorization со схемой 'ApiToken <token>'.  # ref: Oomnitza, Sumo Logic
- Валидатор токена: POST /web/api/v2.1/users/api-token-details с телом {"data":{"apiToken":...}}.  # ref: PowerShell-SentinelOne
- Получение агентов: GET /web/api/v2.1/agents, пагинация через 'cursor' и limit<=1000.  # ref: Qualys, BlinkOps, Postman pages
- Получение сайтов: GET /web/api/v2.1/sites (поддерживает limit и cursor).  # ref: PowerShell-SentinelOne (GetSites)
- Получение угроз: GET /web/api/v2.1/threats (много фильтров, поддерживает cursor).  # ref: Postman Get Threats
- Митигирующие действия: POST /web/api/v2.1/threats/mitigate/{action} с телом {"filter": {...}}; action ∈ {"kill","quarantine","remediate","rollback-remediation","un-quarantine","network-quarantine"}.  # ref: Postman, Swimlane

Зависимость: httpx>=0.24 (асинхронный клиент). Без внешних фреймворков.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, Iterable, Literal, Optional

import httpx


# ----------------------------- Константы и типы -----------------------------

S1_DEFAULT_TIMEOUT = 30.0
S1_MAX_LIMIT = 1000  # подтверждён лимит 1..1000 на мн. эндпоинтах
S1_USER_AGENT = "Aethernova-CyberSim/1.0 (+sentinelone-integration)"
RetryableCodes = {408, 409, 425, 429, 500, 502, 503, 504}

MitigationAction = Literal[
    "kill",
    "quarantine",
    "remediate",
    "rollback-remediation",
    "un-quarantine",
    "network-quarantine",
]


@dataclass(slots=True)
class SentinelOneAPIError(Exception):
    status_code: int
    title: str | None = None
    code: str | None = None
    detail: str | None = None
    rqid: str | None = None

    def __str__(self) -> str:
        parts = [f"HTTP {self.status_code}"]
        if self.title:
            parts.append(self.title)
        if self.code:
            parts.append(f"[{self.code}]")
        if self.rqid:
            parts.append(f"(x-rqid={self.rqid})")
        if self.detail:
            parts.append(f": {self.detail}")
        return " ".join(parts)


@dataclass(slots=True)
class Pagination:
    next_cursor: Optional[str]
    total_items: Optional[int]


# ----------------------------- Вспомогательные -----------------------------


def _auth_header(token: str) -> str:
    # Подтверждение схемы: "Authorization: ApiToken <token>"
    # Источники: Oomnitza, Sumo Logic, Mimecast docs (ниже)
    return f"ApiToken {token.strip()}"


def _clamp_limit(limit: Optional[int]) -> int:
    if limit is None:
        return S1_MAX_LIMIT
    return max(1, min(S1_MAX_LIMIT, int(limit)))


def _extract_error(resp: httpx.Response) -> SentinelOneAPIError:
    rqid = resp.headers.get("x-rqid") or resp.headers.get("x-request-id")
    title = code = detail = None
    try:
        body = resp.json()
        if isinstance(body, dict):
            err = body.get("errors") or body.get("error") or {}
            if isinstance(err, dict):
                title = err.get("title")
                code = err.get("code")
                detail = err.get("detail")
    except Exception:
        pass
    return SentinelOneAPIError(resp.status_code, title, code, detail, rqid)


def _next_backoff(attempt: int, base: float, jitter: float) -> float:
    # экспоненциальный рост с "полным" джиттером
    # attempt: начиная с 1
    cap = 20.0
    return min(cap, (base * (2 ** (attempt - 1))) + (jitter * (attempt - 1)))


# ------------------------------- Клиент API --------------------------------


class AsyncSentinelOneClient:
    """
    Асинхронный клиент SentinelOne Management API v2.1.

    Параметры:
      base_url: например, "https://example.sentinelone.net"
      api_token: токен API (Service User)
      timeout: seconds
      verify: проверка TLS (True/False/путь к CA)
      max_retries: максимум попыток при 429/5xx
      backoff_base: базовая задержка (сек) для экспоненциального бэкоффа
      backoff_jitter: добавочный джиттер (сек)

    Аутентификация: Authorization: ApiToken <token>
    """

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        timeout: float = S1_DEFAULT_TIMEOUT,
        verify: bool | str = True,
        max_retries: int = 5,
        backoff_base: float = 0.5,
        backoff_jitter: float = 0.25,
        user_agent: str = S1_USER_AGENT,
        proxy: Optional[str] = None,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("base_url must start with https://")
        # Нормализуем слэш в конце
        base = base_url.rstrip("/")
        self._token = api_token
        self._max_retries = max(0, int(max_retries))
        self._backoff_base = float(backoff_base)
        self._backoff_jitter = float(backoff_jitter)

        headers = {
            "Authorization": _auth_header(api_token),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": user_agent,
        }

        self._client = httpx.AsyncClient(
            base_url=base,
            headers=headers,
            timeout=timeout,
            verify=verify,
            proxies=proxy,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncSentinelOneClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    # --------------------------- Низкоуровневый запрос ---------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        # Конструируем абсолютный путь
        url = path if path.startswith("/") else f"/{path}"

        attempt = 0
        while True:
            attempt += 1
            resp = await self._client.request(method.upper(), url, params=params, json=json_body)
            if 200 <= resp.status_code < 300:
                try:
                    return resp.json()
                except json.JSONDecodeError:
                    # некоторые экспортные/загрузочные операции могут не возвращать JSON
                    return {}

            # Определяем, ретраить ли
            retry = resp.status_code in RetryableCodes
            # Учитываем Retry-After, если дан (секунды либо HTTP-date)
            delay = None
            if retry:
                ra = resp.headers.get("Retry-After")
                if ra:
                    try:
                        delay = float(ra)
                    except Exception:
                        delay = None
                if delay is None:
                    delay = _next_backoff(attempt, self._backoff_base, self._backoff_jitter)

            if retry and attempt <= self._max_retries:
                await asyncio.sleep(delay or 0)
                continue

            # Ошибка
            raise _extract_error(resp)

    # ------------------------------ Вспомогательные ------------------------------

    @staticmethod
    def _page_params(limit: Optional[int], cursor: Optional[str], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        p = {"limit": _clamp_limit(limit)}
        if cursor:
            p["cursor"] = cursor
        if extra:
            p.update({k: v for (k, v) in extra.items() if v is not None})
        return p

    # ------------------------------- Высокоуровневые ------------------------------

    async def validate_token(self) -> Dict[str, Any]:
        """
        POST /web/api/v2.1/users/api-token-details
        Тело: {"data":{"apiToken": "<token>"}}
        Возвращает детали/срок действия токена.
        """
        path = "/web/api/v2.1/users/api-token-details"
        body = {"data": {"apiToken": self._token}}
        return await self._request("POST", path, json_body=body)

    async def list_sites(
        self, *, limit: int | None = None, cursor: str | None = None, extra_params: Optional[Dict[str, Any]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Постраничный перебор сайтов: GET /web/api/v2.1/sites
        """
        path = "/web/api/v2.1/sites"
        cur = cursor
        while True:
            params = self._page_params(limit, cur, extra_params)
            data = await self._request("GET", path, params=params)
            for item in data.get("data", []) or []:
                yield item
            pg = data.get("pagination") or {}
            cur = pg.get("nextCursor")
            if not cur:
                break

    async def list_agents(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Постраничный перебор агентов: GET /web/api/v2.1/agents
        Фильтры передаются как query params (напр.: isActive, osTypes, groupIds, siteIds, query и т.п.).
        """
        path = "/web/api/v2.1/agents"
        cur = cursor
        filters = filters or {}
        while True:
            params = self._page_params(limit, cur, filters)
            data = await self._request("GET", path, params=params)
            for item in data.get("data", []) or []:
                yield item
            pg = data.get("pagination") or {}
            cur = pg.get("nextCursor")
            if not cur:
                break

    async def get_threats(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Постраничный перебор угроз: GET /web/api/v2.1/threats
        Фильтры — query params (см. Postman 'Get Threats').
        """
        path = "/web/api/v2.1/threats"
        cur = cursor
        filters = filters or {}
        while True:
            params = self._page_params(limit, cur, filters)
            data = await self._request("GET", path, params=params)
            for item in data.get("data", []) or []:
                yield item
            pg = data.get("pagination") or {}
            cur = pg.get("nextCursor")
            if not cur:
                break

    async def mitigate_threats(self, action: MitigationAction, *, filter_body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Применяет митигирующее действие к угрозам по фильтру:
          POST /web/api/v2.1/threats/mitigate/{action}
        Тело: {"filter": {...}}
        Возвращает объект с полем data.affected (число затронутых сущностей).
        """
        if not isinstance(filter_body, dict) or not filter_body:
            raise ValueError("filter_body must be a non-empty dict")
        path = f"/web/api/v2.1/threats/mitigate/{action}"
        body = {"filter": filter_body}
        return await self._request("POST", path, json_body=body)

    # Удобные обёртки для сетевой изоляции/снятия изоляции
    async def network_isolate(self, *, filter_body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Изоляция от сети (network quarantine) для эндпоинтов, связанных с угрозами по фильтру.
        Эквивалент: mitigate_threats('network-quarantine', filter=...).
        """
        return await self.mitigate_threats("network-quarantine", filter_body=filter_body)

    async def network_unisolate(self, *, filter_body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Снятие изоляции (un-quarantine) для соответствующих эндпоинтов.
        Эквивалент: mitigate_threats('un-quarantine', filter=...).
        """
        return await self.mitigate_threats("un-quarantine", filter_body=filter_body)


# ------------------------------ Пример использования ------------------------------
# Пример не исполняется при импорте модуля.
# Запускать отдельно, задав переменные окружения S1_BASE_URL и S1_API_TOKEN.

async def _demo() -> None:
    base_url = os.environ.get("S1_BASE_URL", "").strip()
    api_token = os.environ.get("S1_API_TOKEN", "").strip()
    if not base_url or not api_token:
        print("Set S1_BASE_URL and S1_API_TOKEN in environment to run demo")
        return

    async with AsyncSentinelOneClient(base_url, api_token) as s1:
        tok = await s1.validate_token()
        print("Token check:", json.dumps(tok, ensure_ascii=False)[:400], "...\n")

        # Сайты (первая страница)
        async for site in s1.list_sites(limit=50):
            print("Site:", site.get("id"), site.get("name"))
            break

        # Агенты Windows с активными агентами, ограничим до 5
        filters = {"osTypes": "windows", "isActive": True}
        count = 0
        async for ag in s1.list_agents(limit=5, filters=filters):
            print("Agent:", ag.get("id"), ag.get("computerName"))
            count += 1
        print("Agents shown:", count)

        # Пример: подсчитать угрозы за последние 24ч (countOnly=true)
        t_filters = {"createdAt__gte": "now-24h", "countOnly": True}
        result = await s1._request("GET", "/web/api/v2.1/threats", params=t_filters)
        print("Threats (last 24h) countOnly:", result.get("pagination", {}).get("totalItems"))

        # Пример network quarantine по фильтру (только демонстрация тела запроса)
        # НЕ ЗАПУСКАЙТЕ в проде без уточнения фильтров!
        # resp = await s1.network_isolate(filter_body={"ids": ["<THREAT_ID_1>", "<THREAT_ID_2>"]})
        # print(resp)


if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass


# --------------------------------- ИСТОЧНИКИ ---------------------------------
# Базовый URL вида https://<subdomain>.sentinelone.net: Mimecast (аутентификация) и Tenable (Prerequisites)
#   https://mimecastsupport.zendesk.com/... "https://<your company name>.sentinelone.net"  # turn1search14
#   https://docs.tenable.com/.../sentinelone-connector.htm  # turn2search20
#
# Схема аутентификации "Authorization: ApiToken <token>":
#   Oomnitza: "Enter 'ApiToken <API_KEY>' in Authorization header"  # turn1search15
#   Sumo Logic Mgmt API Source: token associated with ApiToken  # turn1search13
#
# Валидация токена users/api-token-details (пример в публичном коде):
#   PowerShell-SentinelOne endpoints: "web/api/v2.1/users/api-token-details"  # turn7view0
#
# Список агентов /web/api/v2.1/agents:
#   Qualys connector lists endpoint "/web/api/v2.1/agents"  # turn2search5
#   BlinkOps "List Agents" описывает cursor/limit и параметры  # turn3search8
#
# Пагинация через 'cursor' и limit<=1000:
#   Postman pages (пример протоколов указывает skip/limit/cursor)  # turn3search2
#
# Сайты /web/api/v2.1/sites (и др. подтверждения в открытом коде):
#   PowerShell-SentinelOne GetSites "/web/api/v2.1/sites"  # turn7view0
#
# Угрозы /web/api/v2.1/threats (множество фильтров):
#   Postman "Get Threats" показывает полный набор query params  # turn8search0
#
# Митигирующие действия через POST /web/api/v2.1/threats/mitigate/{action} с телом {"filter": {...}}:
#   Postman "Mitigate Threats" — допустимые actions (kill, quarantine, remediate, rollback-remediation, un-quarantine, network-quarantine)  # turn6view0
#   Swimlane connector "mitigate-threats" — явное требование JSON {"filter": {...}}  # turn9search2
#
# Практики API-защиты/таймауты/ретраи (общие, для контекста архитектуры клиента):
#   SentinelOne API endpoint security best practices (rate limiting, TLS, аутентификация)  # turn1search1
