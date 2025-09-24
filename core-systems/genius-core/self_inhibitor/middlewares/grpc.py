# -*- coding: utf-8 -*-
"""
Genius Core — Self-Inhibitor gRPC Middleware
-------------------------------------------
Промышленный перехватчик безопасности для gRPC (sync и asyncio):
- До/после вызова RPC: поиск PII/секретов, prompt-injection, опасных команд.
- Решения: ALLOW / SANITIZE / BLOCK / REVIEW (по умолчанию REVIEW трактуется как SANITIZE).
- Поддержка unary-unary, unary-stream, stream-unary, stream-stream.
- Пер-методная политика: allow/deny, редактирование включено/выключено, макс. размер полезной нагрузки.
- Настраиваемые extractor/mutator для сообщений (protobuf или plain-объекты).
- Безопасное прерывание через grpc.StatusCode.PERMISSION_DENIED и подробное объяснение.
- Легковесно: стандартная библиотека + grpcio; protobuf/json_format — опционально.

Интеграция (sync):
    from core_systems.genius_core.security.self_inhibitor.middlewares.grpc import SelfInhibitorGrpc, InhibitorConfig
    inhibitor = SelfInhibitorGrpc(InhibitorConfig())
    server = grpc.server(..., interceptors=[inhibitor.sync()])

Интеграция (asyncio):
    aio_inhibitor = SelfInhibitorGrpc(InhibitorConfig())
    aio_server = grpc.aio.server(interceptors=[aio_inhibitor.asyncio()])

При необходимости укажите собственные extractor/mutator:
    inhibitor = SelfInhibitorGrpc(cfg, extract_text=my_extract, mutate_text=my_mutate)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, AsyncIterator, Callable, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

import grpc  # type: ignore

# Пробуем protobuf опционально
try:
    from google.protobuf.message import Message as _PBMessage  # type: ignore
    from google.protobuf.json_format import MessageToDict  # type: ignore
    _HAS_PB = True
except Exception:
    _HAS_PB = False

# ---------------------------
# Логирование
# ---------------------------

_log = logging.getLogger("genius.self_inhibitor.grpc")
if not _log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(_h)
_log.setLevel(getattr(logging, os.getenv("GENIUS_INHIBITOR_LOG_LEVEL", "INFO").upper(), logging.INFO))

# ---------------------------
# Модель решений
# ---------------------------

class Risk(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class Action(Enum):
    ALLOW = auto()
    SANITIZE = auto()
    REVIEW = auto()   # трактуется как SANITIZE, но помечается как требующий ревью
    BLOCK = auto()

@dataclass
class Decision:
    action: Action
    risk: Risk
    reasons: List[str] = field(default_factory=list)
    matched: List[str] = field(default_factory=list)
    transformed_text: Optional[str] = None

    def blocked(self) -> bool:
        return self.action == Action.BLOCK

# ---------------------------
# Конфигурация
# ---------------------------

@dataclass
class MethodPolicy:
    allow: bool = True
    redact: bool = True
    max_payload_bytes: int = 2_000_000  # 2MB
    require_auth_metadata: Optional[str] = None  # например, "authorization"

@dataclass
class InhibitorConfig:
    redaction_token: str = "***"
    redaction_preserve_length: bool = False
    # глобальные тумблеры
    enable_pii: bool = True
    enable_secrets: bool = True
    enable_injection: bool = True
    enable_dangerous_cmds: bool = True
    enable_output_scan: bool = True
    # поведение REVIEW
    treat_review_as_sanitize: bool = True
    # политики по методам (ключ — полное имя RPC "/pkg.Service/Method" или префикс)
    method_policies: Dict[str, MethodPolicy] = field(default_factory=dict)
    # лимит на текст (для тяжелых проверок)
    heavy_check_max_chars: int = 32_000

    # Паттерны
    pii_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=lambda: [
        ("email", re.compile(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b")),
        ("phone", re.compile(r"(?i)\+?\d[\d\-\s()]{7,}\d")),
        ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")),
        ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
        ("ccn", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ])
    secret_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=lambda: [
        ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("pem_private_key", re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----")),
        ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
        ("pat_token", re.compile(r"(?i)\b(token|bearer|apikey|api_key|secret)\b.{0,3}[=:].{6,}")),
        ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ])
    injection_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=lambda: [
        ("ignore_prev", re.compile(r"(?i)\b(ignore|disregard)\s+previous\s+(instructions|rules)")),
        ("reveal_system", re.compile(r"(?i)\b(reveal|show)\s+(system|developer).*(prompt|instructions)\b")),
        ("act_as", re.compile(r"(?i)\bact\s+as\b.*\b(dan|developer mode|root|sudo)\b")),
        ("bypass", re.compile(r"(?i)\b(jailbreak|bypass|override)\b")),
    ])
    dangerous_cmds: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"(?i)\brm\s+-rf\b"),
        re.compile(r"(?i)curl\s+.*\|\s*sh\b"),
        re.compile(r"(?i)\bwget\s+.*\|\s*sh\b"),
        re.compile(r":\(\)\s*\{\s*:\|\:&\s*\};:"),  # fork bomb
    ])

# ---------------------------
# Движок анализа и санитизации
# ---------------------------

def _mask(val: str, token: str, preserve_len: bool) -> str:
    if not preserve_len:
        return token
    # сохраним длину для визуальной телеметрии
    return "".join("•" if ch.strip() else ch for ch in val)

def _findall(patterns: List[Tuple[str, re.Pattern]], text: str) -> List[Tuple[str, Tuple[int, int], str]]:
    out: List[Tuple[str, Tuple[int, int], str]] = []
    for pid, rx in patterns:
        for m in rx.finditer(text):
            out.append((pid, m.span(), m.group(0)))
    return out

class InhibitorEngine:
    def __init__(self, cfg: InhibitorConfig):
        self.cfg = cfg

    def evaluate_input(self, text: str) -> Decision:
        if not text:
            return Decision(Action.ALLOW, Risk.LOW, [])
        matched: List[str] = []
        reasons: List[str] = []
        transformed = text

        if self.cfg.enable_pii:
            hits = _findall(self.cfg.pii_patterns, text)
            if hits:
                matched += [f"pii:{h[0]}" for h in hits]
                reasons.append("PII detected")
                for _, _, val in hits:
                    transformed = transformed.replace(val, _mask(val, self.cfg.redaction_token, self.cfg.redaction_preserve_length))

        high_risk = False
        if self.cfg.enable_secrets:
            sh = _findall(self.cfg.secret_patterns, text)
            if sh:
                matched += [f"secret:{h[0]}" for h in sh]
                reasons.append("Secret detected")
                high_risk = True
                for _, _, val in sh:
                    transformed = transformed.replace(val, _mask(val, self.cfg.redaction_token, self.cfg.redaction_preserve_length))

        inj = []
        if self.cfg.enable_injection:
            inj = _findall(self.cfg.injection_patterns, text)
            if inj:
                matched += [f"injection:{h[0]}" for h in inj]
                reasons.append("Prompt-injection")

        danger = []
        if self.cfg.enable_dangerous_cmds:
            for rx in self.cfg.dangerous_cmds:
                if rx.search(text):
                    danger.append(rx.pattern)
            if danger:
                matched += [f"cmd:{d}" for d in danger]
                reasons.append("Dangerous command")

        if danger or high_risk:
            return Decision(Action.BLOCK, Risk.CRITICAL, reasons, matched)

        if inj:
            # вырезаем явные инструкции обхода
            for _, _, val in inj:
                transformed = transformed.replace(val, "")
            return Decision(Action.SANITIZE, Risk.HIGH, reasons, matched, transformed)

        if matched:
            return Decision(Action.SANITIZE, Risk.MEDIUM, reasons, matched, transformed)

        return Decision(Action.ALLOW, Risk.LOW, [])

    def evaluate_output(self, text: str) -> Decision:
        if not self.cfg.enable_output_scan or not text:
            return Decision(Action.ALLOW, Risk.LOW, [])
        # симметричное маскирование PII/секретов в ответе
        matched: List[str] = []
        transformed = text
        if self.cfg.enable_pii:
            for pid, _, val in _findall(self.cfg.pii_patterns, text):
                transformed = transformed.replace(val, _mask(val, self.cfg.redaction_token, self.cfg.redaction_preserve_length))
                matched.append(f"pii_out:{pid}")
        if self.cfg.enable_secrets:
            for pid, _, val in _findall(self.cfg.secret_patterns, text):
                transformed = transformed.replace(val, _mask(val, self.cfg.redaction_token, self.cfg.redaction_preserve_length))
                matched.append(f"secret_out:{pid}")
        if matched:
            return Decision(Action.SANITIZE, Risk.MEDIUM, ["Output redacted"], matched, transformed)
        return Decision(Action.ALLOW, Risk.LOW, [])

# ---------------------------
# Экстракция и мутация текста в сообщениях
# ---------------------------

# По умолчанию пытаемся извлечь очевидные поля
_DEFAULT_TEXT_FIELDS = ("text", "prompt", "query", "content")

def default_extract_text(msg: Any) -> Optional[str]:
    if msg is None:
        return None
    # protobuf → dict (опционально)
    if _HAS_PB and isinstance(msg, _PBMessage):
        try:
            d = MessageToDict(msg, preserving_proto_field_name=True)
            # Ищем популярные поля
            for f in _DEFAULT_TEXT_FIELDS:
                if isinstance(d.get(f), str):
                    return d[f]
            # Вложенное delta.text
            delta = d.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("text"), str):
                return delta["text"]
        except Exception:
            pass
    # Пытаемся обратиться к атрибутам напрямую
    for f in _DEFAULT_TEXT_FIELDS:
        if hasattr(msg, f):
            val = getattr(msg, f)
            if isinstance(val, str):
                return val
    # fallback — ничего не извлекаем
    return None

def default_mutate_text(msg: Any, new_text: str) -> Any:
    if msg is None:
        return msg
    # protobuf — пробуем прямую установку атрибута (часто доступно как property)
    for f in _DEFAULT_TEXT_FIELDS:
        if hasattr(msg, f):
            try:
                setattr(msg, f, new_text)
                return msg
            except Exception:
                continue
    # delta.text
    if hasattr(msg, "delta") and hasattr(getattr(msg, "delta"), "text"):
        try:
            getattr(msg, "delta").text = new_text
            return msg
        except Exception:
            pass
    # если ничего не получилось — оставляем как есть
    return msg

# ---------------------------
# gRPC Interceptors
# ---------------------------

class SelfInhibitorGrpc:
    """
    Фабрика перехватчиков.
    """
    def __init__(
        self,
        cfg: InhibitorConfig,
        engine: Optional[InhibitorEngine] = None,
        extract_text: Callable[[Any], Optional[str]] = default_extract_text,
        mutate_text: Callable[[Any, str], Any] = default_mutate_text,
    ):
        self.cfg = cfg
        self.engine = engine or InhibitorEngine(cfg)
        self.extract_text = extract_text
        self.mutate_text = mutate_text

    # ---- Политика per-method ----
    def _policy_for(self, method_full: str) -> MethodPolicy:
        # точное совпадение или префикс
        for key, pol in self.cfg.method_policies.items():
            if method_full == key or method_full.startswith(key.rstrip("*")):
                return pol
        return MethodPolicy()

    # ---- Общая логика проверки входа/выхода ----
    def _check_request(self, method: str, metadata: Mapping[str, str], msg: Any) -> Decision:
        pol = self._policy_for(method)
        if not pol.allow:
            return Decision(Action.BLOCK, Risk.MEDIUM, [f"method '{method}' denied by policy"], ["policy:deny"])
        if pol.require_auth_metadata:
            if pol.require_auth_metadata.lower() not in {k.lower() for k, _ in metadata.items()}:
                return Decision(Action.BLOCK, Risk.MEDIUM, [f"missing required metadata '{pol.require_auth_metadata}'"], ["policy:auth_required"])
        # грубая оценка размера
        try:
            size = len(bytes(msg)) if hasattr(msg, "__bytes__") else None
        except Exception:
            size = None
        if size is not None and size > pol.max_payload_bytes:
            return Decision(Action.BLOCK, Risk.MEDIUM, [f"payload too large: {size} > {pol.max_payload_bytes}"], ["policy:size_limit"])

        text = self.extract_text(msg)
        if not text:
            return Decision(Action.ALLOW, Risk.LOW, [])
        return self.engine.evaluate_input(text)

    def _check_response(self, method: str, msg: Any) -> Decision:
        if not self.cfg.enable_output_scan:
            return Decision(Action.ALLOW, Risk.LOW, [])
        text = self.extract_text(msg)
        if not text:
            return Decision(Action.ALLOW, Risk.LOW, [])
        return self.engine.evaluate_output(text)

    # ---- Sync interceptor ----
    class _Sync(grpc.ServerInterceptor):
        def __init__(self, outer: "SelfInhibitorGrpc"):
            self.o = outer

        def intercept_service(self, continuation, handler_call_details):
            method = handler_call_details.method or "unknown"
            md = dict(handler_call_details.invocation_metadata or [])
            policy = self.o._policy_for(method)

            handler = continuation(handler_call_details)
            if handler is None:
                return None

            # unary-unary
            if handler.unary_unary:
                def _wrapped_unary_unary(req, ctx):
                    dec = self.o._check_request(method, md, req)
                    if dec.blocked():
                        ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(dec.reasons))
                    if dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and dec.transformed_text:
                        req = self.o.mutate_text(req, dec.transformed_text)

                    resp = handler.unary_unary(req, ctx)
                    out_dec = self.o._check_response(method, resp)
                    if out_dec.blocked():
                        ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(out_dec.reasons))
                    if out_dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and out_dec.transformed_text:
                        resp = self.o.mutate_text(resp, out_dec.transformed_text)
                    return resp

                return grpc.unary_unary_rpc_method_handler(
                    _wrapped_unary_unary,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            # unary-stream
            if handler.unary_stream:
                def _wrapped_unary_stream(req, ctx):
                    dec = self.o._check_request(method, md, req)
                    if dec.blocked():
                        ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(dec.reasons))
                    if dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and dec.transformed_text:
                        req = self.o.mutate_text(req, dec.transformed_text)

                    inner_it = handler.unary_stream(req, ctx)

                    def _gen():
                        for resp in inner_it:
                            out_dec = self.o._check_response(method, resp)
                            if out_dec.blocked():
                                ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(out_dec.reasons))
                            if out_dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and out_dec.transformed_text:
                                resp = self.o.mutate_text(resp, out_dec.transformed_text)
                            yield resp
                    return _gen()
                return grpc.unary_stream_rpc_method_handler(
                    _wrapped_unary_stream,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            # stream-unary
            if handler.stream_unary:
                def _wrapped_stream_unary(req_iter, ctx):
                    def _in_gen():
                        for req in req_iter:
                            dec = self.o._check_request(method, md, req)
                            if dec.blocked():
                                ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(dec.reasons))
                            if dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and dec.transformed_text:
                                req = self.o.mutate_text(req, dec.transformed_text)
                            yield req
                    resp = handler.stream_unary(_in_gen(), ctx)
                    out_dec = self.o._check_response(method, resp)
                    if out_dec.blocked():
                        ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(out_dec.reasons))
                    if out_dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and out_dec.transformed_text:
                        resp = self.o.mutate_text(resp, out_dec.transformed_text)
                    return resp
                return grpc.stream_unary_rpc_method_handler(
                    _wrapped_stream_unary,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            # stream-stream
            if handler.stream_stream:
                def _wrapped_stream_stream(req_iter, ctx):
                    def _in_gen():
                        for req in req_iter:
                            dec = self.o._check_request(method, md, req)
                            if dec.blocked():
                                ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(dec.reasons))
                            if dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and dec.transformed_text:
                                req = self.o.mutate_text(req, dec.transformed_text)
                            yield req

                    inner_it = handler.stream_stream(_in_gen(), ctx)

                    def _out_gen():
                        for resp in inner_it:
                            out_dec = self.o._check_response(method, resp)
                            if out_dec.blocked():
                                ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(out_dec.reasons))
                            if out_dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and out_dec.transformed_text:
                                resp = self.o.mutate_text(resp, out_dec.transformed_text)
                            yield resp
                    return _out_gen()
                return grpc.stream_stream_rpc_method_handler(
                    _wrapped_stream_stream,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            # fallback
            return handler

    # ---- Async interceptor ----
    class _Aio(grpc.aio.ServerInterceptor):  # type: ignore[attr-defined]
        def __init__(self, outer: "SelfInhibitorGrpc"):
            self.o = outer

        async def intercept_service(self, continuation, handler_call_details):
            method = handler_call_details.method or "unknown"
            md = dict(handler_call_details.invocation_metadata or [])
            policy = self.o._policy_for(method)

            handler = await continuation(handler_call_details)
            if handler is None:
                return None

            # unary-unary
            if handler.unary_unary:
                async def _wrapped_unary_unary(req, ctx):
                    dec = self.o._check_request(method, md, req)
                    if dec.blocked():
                        await ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(dec.reasons))
                    if dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and dec.transformed_text:
                        req = self.o.mutate_text(req, dec.transformed_text)

                    resp = await handler.unary_unary(req, ctx)
                    out_dec = self.o._check_response(method, resp)
                    if out_dec.blocked():
                        await ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(out_dec.reasons))
                    if out_dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and out_dec.transformed_text:
                        resp = self.o.mutate_text(resp, out_dec.transformed_text)
                    return resp
                return grpc.aio.unary_unary_rpc_method_handler(
                    _wrapped_unary_unary,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            # unary-stream
            if handler.unary_stream:
                async def _wrapped_unary_stream(req, ctx):
                    dec = self.o._check_request(method, md, req)
                    if dec.blocked():
                        await ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(dec.reasons))
                    if dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and dec.transformed_text:
                        req = self.o.mutate_text(req, dec.transformed_text)

                    inner_it = await handler.unary_stream(req, ctx)

                    async def _gen():
                        async for resp in inner_it:
                            out_dec = self.o._check_response(method, resp)
                            if out_dec.blocked():
                                await ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(out_dec.reasons))
                            if out_dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and out_dec.transformed_text:
                                resp = self.o.mutate_text(resp, out_dec.transformed_text)
                            yield resp
                    return _gen()
                return grpc.aio.unary_stream_rpc_method_handler(
                    _wrapped_unary_stream,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            # stream-unary
            if handler.stream_unary:
                async def _wrapped_stream_unary(req_iter, ctx):
                    async def _in_gen():
                        async for req in req_iter:
                            dec = self.o._check_request(method, md, req)
                            if dec.blocked():
                                await ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(dec.reasons))
                            if dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and dec.transformed_text:
                                req = self.o.mutate_text(req, dec.transformed_text)
                            yield req
                    resp = await handler.stream_unary(_in_gen(), ctx)
                    out_dec = self.o._check_response(method, resp)
                    if out_dec.blocked():
                        await ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(out_dec.reasons))
                    if out_dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and out_dec.transformed_text:
                        resp = self.o.mutate_text(resp, out_dec.transformed_text)
                    return resp
                return grpc.aio.stream_unary_rpc_method_handler(
                    _wrapped_stream_unary,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            # stream-stream
            if handler.stream_stream:
                async def _wrapped_stream_stream(req_iter, ctx):
                    async def _in_gen():
                        async for req in req_iter:
                            dec = self.o._check_request(method, md, req)
                            if dec.blocked():
                                await ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(dec.reasons))
                            if dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and dec.transformed_text:
                                req = self.o.mutate_text(req, dec.transformed_text)
                            yield req

                    inner_it = await handler.stream_stream(_in_gen(), ctx)

                    async def _out_gen():
                        async for resp in inner_it:
                            out_dec = self.o._check_response(method, resp)
                            if out_dec.blocked():
                                await ctx.abort(grpc.StatusCode.PERMISSION_DENIED, "; ".join(out_dec.reasons))
                            if out_dec.action in (Action.SANITIZE, Action.REVIEW) and policy.redact and out_dec.transformed_text:
                                resp = self.o.mutate_text(resp, out_dec.transformed_text)
                            yield resp
                    return _out_gen()
                return grpc.aio.stream_stream_rpc_method_handler(
                    _wrapped_stream_stream,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            return handler

    # ---- Публичные фабричные методы ----
    def sync(self) -> grpc.ServerInterceptor:
        return SelfInhibitorGrpc._Sync(self)

    def asyncio(self) -> grpc.aio.ServerInterceptor:  # type: ignore[attr-defined]
        return SelfInhibitorGrpc._Aio(self)

# ---------------------------
# Пример локального запуска
# ---------------------------

if __name__ == "__main__":
    # Пример конфигурации per-method
    cfg = InhibitorConfig(
        method_policies={
            "/omni.Chat/Complete": MethodPolicy(allow=True, redact=True, max_payload_bytes=1_000_000, require_auth_metadata="authorization"),
            "/omni.Admin/*": MethodPolicy(allow=False),  # запрет по префиксу
        }
    )
    inh = SelfInhibitorGrpc(cfg)
    _log.info("Self-Inhibitor gRPC ready (demo)")
