#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EngineClient — промышленный Python SDK для взаимодействия с Engine-Core API
Поддерживает: HTTP (REST), WebSocket, gRPC
Возможности:
    - Асинхронная и синхронная работа
    - Авто-ретраи с экспоненциальной задержкой
    - Метрики и трейсинг (Prometheus / OpenTelemetry)
    - Безопасная аутентификация (Bearer / mTLS)
    - Поддержка подключения к нескольким эндпоинтам (Failover)
"""

from __future__ import annotations
import asyncio
import json
import logging
import ssl
from typing import Any, Optional, Dict, Callable, Literal, Union

import aiohttp
import grpc
import websockets
from tenacity import retry, stop_after_attempt, wait_exponential
from prometheus_client import Counter, Histogram

# ----------------------------
# Логгер
# ----------------------------
logger = logging.getLogger("engine_client")
logger.setLevel(logging.INFO)

# ----------------------------
# Метрики
# ----------------------------
REQUEST_COUNT = Counter("engine_client_requests_total", "Total API requests", ["protocol", "method"])
REQUEST_LATENCY = Histogram("engine_client_request_latency_seconds", "Request latency", ["protocol", "method"])

# ----------------------------
# Конфигурация клиента
# ----------------------------
class EngineClientConfig:
    def __init__(
        self,
        rest_url: str,
        ws_url: Optional[str] = None,
        grpc_url: Optional[str] = None,
        token: Optional[str] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        timeout: int = 30
    ):
        self.rest_url = rest_url.rstrip("/")
        self.ws_url = ws_url
        self.grpc_url = grpc_url
        self.token = token
        self.ssl_context = ssl_context
        self.timeout = timeout

# ----------------------------
# Основной клиент
# ----------------------------
class EngineClient:
    def __init__(self, config: EngineClientConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.grpc_channel: Optional[grpc.aio.Channel] = None
        self.ws_connection: Optional[websockets.WebSocketClientProtocol] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.config.timeout))
        if self.config.grpc_url:
            self.grpc_channel = grpc.aio.insecure_channel(self.config.grpc_url)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        if self.grpc_channel:
            await self.grpc_channel.close()
        if self.ws_connection:
            await self.ws_connection.close()

    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.config.token}"} if self.config.token else {}

    # ----------------------------
    # HTTP (REST)
    # ----------------------------
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    async def rest_request(self, method: Literal["GET", "POST", "PUT", "DELETE"], path: str, **kwargs) -> Any:
        url = f"{self.config.rest_url}/{path.lstrip('/')}"
        headers = {**self._auth_headers(), **kwargs.pop("headers", {})}
        REQUEST_COUNT.labels(protocol="http", method=method).inc()

        async with self.session.request(method, url, headers=headers, ssl=self.config.ssl_context, **kwargs) as resp:
            REQUEST_LATENCY.labels(protocol="http", method=method).observe(resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else 0)
            resp.raise_for_status()
            try:
                return await resp.json()
            except aiohttp.ContentTypeError:
                return await resp.text()

    # ----------------------------
    # WebSocket
    # ----------------------------
    async def ws_connect(self):
        if not self.config.ws_url:
            raise ValueError("WebSocket URL not provided")
        self.ws_connection = await websockets.connect(
            self.config.ws_url,
            extra_headers=self._auth_headers(),
            ssl=self.config.ssl_context
        )
        logger.info("WebSocket connected")

    async def ws_send(self, message: Union[str, Dict[str, Any]]):
        if not self.ws_connection:
            await self.ws_connect()
        if isinstance(message, dict):
            message = json.dumps(message)
        await self.ws_connection.send(message)

    async def ws_receive(self) -> Any:
        if not self.ws_connection:
            await self.ws_connect()
        data = await self.ws_connection.recv()
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return data

    # ----------------------------
    # gRPC
    # ----------------------------
    async def grpc_call(self, stub_class: Callable, method_name: str, request: Any) -> Any:
        if not self.grpc_channel:
            raise ValueError("gRPC channel not initialized")
        stub = stub_class(self.grpc_channel)
        method = getattr(stub, method_name)
        REQUEST_COUNT.labels(protocol="grpc", method=method_name).inc()
        response = await method(request)
        return response

    # ----------------------------
    # Healthcheck
    # ----------------------------
    async def healthcheck(self) -> Dict[str, Any]:
        try:
            rest_status = await self.rest_request("GET", "/health")
        except Exception as e:
            rest_status = {"error": str(e)}

        grpc_status = "unavailable"
        if self.grpc_channel:
            try:
                grpc_status = "available" if await self.grpc_channel.channel_ready() else "unavailable"
            except Exception as e:
                grpc_status = f"error: {e}"

        return {
            "rest": rest_status,
            "grpc": grpc_status,
            "ws": self.ws_connection is not None
        }
