# cybersecurity-core/cybersecurity/adversary_emulation/integrations/edr/crowdstrike.py
# -*- coding: utf-8 -*-
"""
CrowdStrike Falcon EDR integration (OAuth2, Detects, Hosts containment, Event Streams scaffolding).

Подтвержденные факты:
- Базовые API-хосты по облакам: US-1, US-2, EU-1, Gov. Источник: CrowdStrike Falcon Event Streams Add-on Guide.  # :contentReference[oaicite:6]{index=6}
- OAuth2 Client Credentials: POST /oauth2/token, токен типично валиден ~30 минут. Источники: CrowdStrike TA/документация, практические руководства.  # :contentReference[oaicite:7]{index=7}
- FQL (Falcon Query Language) используется для фильтрации детекций. Источник: FalconPy Detects docs и исходники.  # :contentReference[oaicite:8]{index=8}
- Наличие официальных SDK (в т.ч. FalconPy). Источник: CrowdStrike Developer Docs / FalconPy.  # :contentReference[oaicite:9]{index=9}
- Event Streams — потоковый интерфейс для событий. Источники: CrowdStrike Event Streams Guide / интеграционные мануалы.  # :contentReference[oaicite:10]{index=10}

Назначение:
- Безопасная аутентификация и автообновление токена в памяти (refresh-on-expiry).
- Единый HTTP-клиент с экспоненциальным бэкоффом, джиттером и разбором 429/5xx.
- Утилиты для:
    * Поиска детекций (FQL) с пагинацией.
    * Получения устройств по фильтрам.
    * Изоляции/снятия изоляции хоста (containment/lift).
    * Заготовки Event Streams (инициализация, курсоры).
- Минимум внешних зависимостей: стандартная библиотека + requests (см. секцию импорта).
- Соответствие «промышленным» ожиданиям: таймауты, структурные ошибки, логирование, типизация.

Ограничения:
- Этот модуль не управляет полномочиями API и не проверяет роли/скоупы.
- Для реального продакшна `Event Streams` обычно реализуют отдельным сервисом с очередью/хранилищем.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import time
import typing as t
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from random import random

import requests
from requests import Response, Session

__all__ = [
    "CrowdStrikeConfig",
    "CrowdStrikeClient",
    "CrowdStrikeError",
    "ApiRateLimitError",
    "ApiAuthError",
    "ApiTransientError",
    "Detection",
    "Device",
    "ContainmentResult",
]

# -----------------------------
# Конфигурация и модели
# -----------------------------

# Карта известных публичных API-хостов по облакам (подтверждено документацией).
KNOWN_BASE_URLS: dict[str, str] = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "gov":  "https://api.laggar.gcw.crowdstrike.com",
}

DEFAULT_TIMEOUT = (5.0, 60.0)  # (connect, read) seconds

@dataclass(slots=True)
class CrowdStrikeConfig:
    # Укажите либо cloud="eu-1"/"us-1"/..., либо явный base_url.
    cloud: str = "eu-1"
    base_url: str | None = None

    client_id: str = field(default_factory=lambda: os.getenv("CS_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.getenv("CS_CLIENT_SECRET", ""))

    # Глобальные таймауты HTTP
    timeout: tuple[float, float] = DEFAULT_TIMEOUT

    # HTTP-поведение
    max_retries: int = 5
    backoff_base: float = 0.5  # стартовая задержка
    backoff_max: float = 8.0   # максимум задержки между ретраями
    backoff_jitter: float = 0.25  # доля случайной компоненты

    # Логирование
    log_level: int = logging.INFO

    # Режим аудита трафика (осторожно с чувствительными данными!)
    debug_http: bool = False

    # Граничные размеры страниц и лимиты
    page_limit: int = 100


@dataclass(slots=True)
class Detection:
    id: str
    status: str | None = None
    created: str | None = None
    severity: int | None = None
    device_id: str | None = None
    tactic: str | None = None
    technique: str | None = None
    raw: dict[str, t.Any] = field(default_factory=dict)


@dataclass(slots=True)
class Device:
    device_id: str
    hostname: str | None = None
    platform: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    raw: dict[str, t.Any] = field(default_factory=dict)


@dataclass(slots=True)
class ContainmentResult:
    success: bool
    device_id: str
    action: str
    raw: dict[str, t.Any] = field(default_factory=dict)


# -----------------------------
# Исключения
# -----------------------------

class CrowdStrikeError(RuntimeError):
    pass


class ApiAuthError(CrowdStrikeError):
    pass


class ApiRateLimitError(CrowdStrikeError):
    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ApiTransientError(CrowdStrikeError):
    pass


# -----------------------------
# Вспомогательные функции
# -----------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _compute_backoff(attempt: int, base: float, max_delay: float, jitter: float) -> float:
    # экспоненциальный рост с джиттером
    delay = min(max_delay, base * (2 ** (attempt - 1)))
    return delay * (1.0 - jitter + 2.0 * jitter * random())


# -----------------------------
# Основной клиент
# -----------------------------

class CrowdStrikeClient:
    def __init__(self, cfg: CrowdStrikeConfig) -> None:
        self.cfg = cfg
        self.base_url = cfg.base_url or KNOWN_BASE_URLS.get(cfg.cloud, "")
        if not self.base_url:
            raise ValueError(f"Unknown cloud '{cfg.cloud}' and no base_url provided")

        self._session: Session = requests.Session()
        self._access_token: str | None = None
        self._token_expiry: datetime | None = None

        self.logger = logging.getLogger("crowdstrike")
        self.logger.setLevel(cfg.log_level)
        if not self.logger.handlers:
            h = logging.StreamHandler()
            fmt = logging.Formatter(
                fmt="%(asctime)s %(levelname)s crowdstrike %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            )
            h.setFormatter(fmt)
            self.logger.addHandler(h)
            self.logger.propagate = False

    # ------------- OAuth2 -------------

    def _token_valid(self) -> bool:
        if not self._access_token or not self._token_expiry:
            return False
        # буфер обновления 60 сек
        return _now_utc() + timedelta(seconds=60) < self._token_expiry

    def _authenticate(self) -> None:
        if not self.cfg.client_id or not self.cfg.client_secret:
            raise ApiAuthError("Missing client_id/client_secret")

        url = f"{self.base_url}/oauth2/token"
        data = {
            "client_id": self.cfg.client_id,
            "client_secret": self.cfg.client_secret,
        }
        # grant_type не всегда обязателен, но добавим явно
        data["grant_type"] = "client_credentials"

        resp = self._session.post(url, data=data, timeout=self.cfg.timeout)
        if resp.status_code != HTTPStatus.OK:
            raise ApiAuthError(f"OAuth2 failure: {resp.status_code} {resp.text}")

        payload = resp.json()
        token = payload.get("access_token")
        expires_in = int(payload.get("expires_in", 1800))  # по спецификации около 30 мин
        if not token:
            raise ApiAuthError("OAuth2 response has no access_token")

        self._access_token = token
        self._token_expiry = _now_utc() + timedelta(seconds=expires_in)
        if self.cfg.debug_http:
            self.logger.info("oauth2 token acquired, expires_in=%s", expires_in)

    def _ensure_token(self) -> None:
        if not self._token_valid():
            self._authenticate()

    # ------------- HTTP core -------------

    def _headers(self) -> dict[str, str]:
        self._ensure_token()
        assert self._access_token
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, t.Any] | None = None,
        json_body: dict[str, t.Any] | None = None,
        expected: set[int] | None = None,
    ) -> Response:
        url = f"{self.base_url}{path}"
        expected = expected or {200}
        attempt = 0
        while True:
            attempt += 1
            self._ensure_token()
            headers = self._headers()

            if self.cfg.debug_http:
                self.logger.info(
                    "http %s %s params=%s body=%s",
                    method, url, params, json.dumps(json_body)[:1024] if json_body else None
                )
            resp = self._session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=self.cfg.timeout,
            )

            # Успех?
            if resp.status_code in expected:
                return resp

            # Rate limit?
            if resp.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                ra = resp.headers.get("Retry-After")
                retry_after = float(ra) if ra and ra.isdigit() else None
                if attempt <= self.cfg.max_retries:
                    delay = retry_after or _compute_backoff(
                        attempt, self.cfg.backoff_base, self.cfg.backoff_max, self.cfg.backoff_jitter
                    )
                    self.logger.warning("429 rate limited, retry in %.2fs", delay)
                    time.sleep(delay)
                    continue
                raise ApiRateLimitError("Rate limit exceeded", retry_after=retry_after)

            # Транзиент?
            if resp.status_code >= 500 and attempt <= self.cfg.max_retries:
                delay = _compute_backoff(
                    attempt, self.cfg.backoff_base, self.cfg.backoff_max, self.cfg.backoff_jitter
                )
                self.logger.warning("%s transient error, retry in %.2fs", resp.status_code, delay)
                time.sleep(delay)
                continue

            # 401 — попробуем обновить токен и повторить
            if resp.status_code == HTTPStatus.UNAUTHORIZED and attempt <= self.cfg.max_retries:
                self.logger.warning("401 unauthorized, refreshing token")
                # инвалидируем токен и ретраим
                self._access_token = None
                self._token_expiry = None
                continue

            # Иное — ошибка
            msg = f"API error {resp.status_code}: {resp.text[:1000]}"
            if 400 <= resp.status_code < 500:
                raise CrowdStrikeError(msg)
            raise ApiTransientError(msg)

    # ------------- Detects -------------

    def list_detection_ids(
        self,
        *,
        fql_filter: str = "*",
        sort: str | None = None,
        limit: int | None = None,
        after: str | None = None,
        before: str | None = None,
    ) -> dict[str, t.Any]:
        """
        Возвращает «сырые» данные с идентификаторами детекций (Falcon Detects).
        Использует FQL-фильтр. См. документы FalconPy Detects/FQL.  # :contentReference[oaicite:11]{index=11}
        """
        params: dict[str, t.Any] = {"filter": fql_filter}
        if sort:
            params["sort"] = sort
        if limit:
            params["limit"] = min(limit, self.cfg.page_limit)
        if after:
            params["after"] = after
        if before:
            params["before"] = before

        resp = self._request("GET", "/detects/queries/detects/v1", params=params)
        return resp.json()

    def get_detections(self, ids: list[str]) -> list[Detection]:
        """
        Получает объекты детекций по списку ID.
        """
        if not ids:
            return []
        payload = {"ids": ids[:self.cfg.page_limit]}
        resp = self._request("POST", "/detects/entities/detects/GET/v2", json_body=payload, expected={200})
        data = resp.json()
        resources = data.get("resources", [])
        out: list[Detection] = []
        for r in resources:
            out.append(
                Detection(
                    id=str(r.get("detection_id") or r.get("id")),
                    status=r.get("status"),
                    created=r.get("created_timestamp"),
                    severity=r.get("max_severity_display"),
                    device_id=r.get("device", {}).get("device_id") if isinstance(r.get("device"), dict) else r.get("device_id"),
                    tactic=(r.get("behaviors") or [{}])[0].get("tactic") if r.get("behaviors") else None,
                    technique=(r.get("behaviors") or [{}])[0].get("technique") if r.get("behaviors") else None,
                    raw=r,
                )
            )
        return out

    def search_detections_paged(
        self,
        *,
        fql_filter: str = "*",
        sort: str | None = None,
        page_limit: int | None = None,
        max_pages: int = 100,
    ) -> t.Iterator[list[Detection]]:
        """
        Пагинированный поиск детекций: итератор пачек объектов Detection.
        """
        limit = page_limit or self.cfg.page_limit
        after: str | None = None
        pages = 0
        while pages < max_pages:
            ids_resp = self.list_detection_ids(
                fql_filter=fql_filter, sort=sort, limit=limit, after=after
            )
            resources = ids_resp.get("resources") or []
            if not resources:
                break
            detections = self.get_detections(resources)
            yield detections
            after = ids_resp.get("meta", {}).get("pagination", {}).get("after")
            if not after:
                break
            pages += 1

    # ------------- Devices -------------

    def search_devices(self, fql_filter: str = "*", limit: int | None = None) -> list[Device]:
        """
        Поиск устройств по FQL. Возвращает краткие сведения.
        """
        params = {"filter": fql_filter}
        if limit:
            params["limit"] = min(limit, self.cfg.page_limit)
        # Queries devices
        ids_resp = self._request("GET", "/devices/queries/devices/v1", params=params)
        ids_data = ids_resp.json()
        ids = ids_data.get("resources") or []
        if not ids:
            return []
        # Entities devices
        chunks: list[Device] = []
        for i in range(0, len(ids), self.cfg.page_limit):
            part = ids[i : i + self.cfg.page_limit]
            ent_resp = self._request("GET", "/devices/entities/devices/v2", params={"ids": ",".join(part)})
            ent = ent_resp.json().get("resources") or []
            for r in ent:
                chunks.append(
                    Device(
                        device_id=r.get("device_id") or r.get("aid"),
                        hostname=r.get("hostname"),
                        platform=r.get("platform_name") or r.get("platform"),
                        first_seen=r.get("first_seen"),
                        last_seen=r.get("last_seen"),
                        raw=r,
                    )
                )
        return chunks

    # ------------- Host containment -------------

    def contain_host(self, device_id: str, comment: str | None = None) -> ContainmentResult:
        """
        Изоляция хоста. Требует соответствующих прав API.
        """
        body = {"action_parameters": [{"name": "containment", "value": "contain"}], "ids": [device_id]}
        if comment:
            body["comment"] = comment
        resp = self._request("POST", "/devices/entities/devices-actions/v2", json_body=body, expected={200, 202})
        return ContainmentResult(success=resp.status_code in (200, 202), device_id=device_id, action="contain", raw=resp.json())

    def lift_containment(self, device_id: str, comment: str | None = None) -> ContainmentResult:
        """
        Снятие изоляции. Требует соответствующих прав API.
        """
        body = {"action_parameters": [{"name": "containment", "value": "lift_containment"}], "ids": [device_id]}
        if comment:
            body["comment"] = comment
        resp = self._request("POST", "/devices/entities/devices-actions/v2", json_body=body, expected={200, 202})
        return ContainmentResult(success=resp.status_code in (200, 202), device_id=device_id, action="lift", raw=resp.json())

    # ------------- Event Streams (scaffolding) -------------

    def list_event_streams(self, app_id: str, format: str = "json") -> dict[str, t.Any]:
        """
        Возвращает список доступных потоков событий для интеграции (scaffolding).
        Для полноценного ingestion потребуется устойчивый консьюмер с хранением курсора.
        """
        params = {"appId": app_id, "format": format}
        # Исторически использовались endp. типа /sensors/entities/datafeed/v2 или новые маршруты Event Streams.
        # Конкретный путь может отличаться в зависимости от SKU/организации. Если эндпоинт не доступен — 404.
        # Документацию по Event Streams см. в CrowdStrike Event Streams Guide.  # :contentReference[oaicite:12]{index=12}
        resp = self._request("GET", "/sensors/entities/datafeed/v2", params=params, expected={200, 404})
        return resp.json()

    # ------------- Утилиты -------------

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass


# -----------------------------
# Пример использования (не исполняется при импорте)
# -----------------------------

if __name__ == "__main__":  # pragma: no cover
    cfg = CrowdStrikeConfig(
        cloud=os.getenv("CS_CLOUD", "eu-1"),
        client_id=os.getenv("CS_CLIENT_ID", ""),
        client_secret=os.getenv("CS_CLIENT_SECRET", ""),
        debug_http=bool(int(os.getenv("CS_DEBUG_HTTP", "0"))),
        log_level=logging.INFO,
    )
    cs = CrowdStrikeClient(cfg)

    # 1) Поиск детекций средней и выше важности за последние 24 часа
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fql = f"max_severity_display:>3+created_timestamp:>'{since}'"
    pages = 0
    for batch in cs.search_detections_paged(fql_filter=fql, sort="created_timestamp|desc", page_limit=50, max_pages=5):
        print(f"Batch[{pages}] size={len(batch)}")
        for d in batch:
            print(f"- {d.id} sev={d.severity} dev={d.device_id} tactic={d.tactic}/{d.technique}")
        pages += 1

    # 2) Поиск устройств по имени
    devices = cs.search_devices(fql_filter="hostname:*example*", limit=50)
    print(f"devices: {len(devices)}")

    # 3) Заготовка Event Streams
    streams = cs.list_event_streams(app_id=os.getenv("CS_APP_ID", "aethernova-lab"))
    print(f"streams keys={list(streams.keys())}")

    cs.close()
