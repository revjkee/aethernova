# path: core-systems/genius_core/security/self_inhibitor/middlewares/graphql.py
from __future__ import annotations

import asyncio
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

# -------- Опциональная интеграция с вашим логером --------
try:
    from omnimind.telemetry.logging import get_logger, log_extra, log_context  # noqa: E402
except Exception:  # Лёгкий fallback без зависимости
    import logging

    def get_logger(name: Optional[str] = None):
        return logging.getLogger(name or "genius_core.self_inhibitor")

    def log_extra(**fields: Any) -> Dict[str, Any]:
        return {"extra": {"extra_fields": fields}}

    from contextlib import contextmanager
    @contextmanager
    def log_context(**kwargs: Any):
        yield


# -------- Опциональная зависимость: graphql-core для AST --------
try:
    from graphql import parse, OperationType  # type: ignore
    from graphql.language import (
        DocumentNode,
        OperationDefinitionNode,
        FragmentDefinitionNode,
        FieldNode,
        FragmentSpreadNode,
        InlineFragmentNode,
        SelectionSetNode,
    )  # type: ignore
    _HAS_GRAPHQL = True
except Exception:
    _HAS_GRAPHQL = False
    # Заглушки типов для аннотаций
    DocumentNode = Any  # type: ignore


@dataclass
class InhibitorConfig:
    # Путь(и) GraphQL endpoint. Если пусто — проверяем все HTTP запросы (часто монтируют на /graphql).
    paths: List[str] = field(default_factory=lambda: ["/graphql"])
    # Лимиты формы запроса
    max_query_length: int = 100_000          # символы
    max_variables_bytes: int = 2_000_000     # байты
    max_batch_size: int = 10                 # если используется батч JSON-массивом
    # AST-лимиты
    max_depth: int = 12
    max_complexity: int = 10_000
    block_introspection: bool = True
    # Разрешённые типы операций
    allow_query: bool = True
    allow_mutation: bool = True
    allow_subscription: bool = False
    # Persisted Query режим (Apollo extensions)
    require_persisted: bool = False
    allow_query_text_when_persisted: bool = True  # если True — допускаем и текст запроса при PQ
    # Эвристические запреты
    deny_field_patterns: Iterable[str] = field(default_factory=lambda: [r"^__schema$", r"^__type$"])
    deny_directive_patterns: Iterable[str] = field(default_factory=lambda: [r"^@defer\b", r"^@stream\b"])
    # Эвристика «опасных» значений (можно выключить)
    scan_values_for_malware: bool = True
    value_deny_regexes: Iterable[str] = field(default_factory=lambda: [
        r"(?i)\b(file:////?|smb://|ftp://|gopher://)\b",   # потенциальный SSRF/файлы
        r"(?i)\b(aws_secret_access_key|authorization|api[-_]?key)\b",
        r"(?i)\b(drop\s+table|union\s+select|;--)\b",       # SQL-инъекции (эвристика)
    ])
    # Rate limiting
    rps_per_identity: float = 5.0     # токенов в секунду
    burst_per_identity: float = 10.0  # размер ведра
    # Ответы
    include_reasons_in_errors: bool = False  # в проде лучше False
    # Таймаут чтения тела запроса
    read_body_timeout_s: float = 5.0


class _TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self.rate = float(max(0.001, rate))
        self.capacity = float(max(capacity, self.rate))
        self.tokens = self.capacity
        self.timestamp = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.timestamp
        self.timestamp = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class _RateLimiter:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self._buckets: Dict[str, _TokenBucket] = {}

    def allow(self, identity: str) -> bool:
        b = self._buckets.get(identity)
        if b is None:
            b = _TokenBucket(self.rate, self.capacity)
            self._buckets[identity] = b
        return b.allow(1.0)


class SelfInhibitorGraphQLMiddleware:
    """
    ASGI-middleware для охраны GraphQL-эндпоинтов.

    Функции:
      • Ограничение размера тела и переменных
      • Запрет/разрешение типов операций
      • Запрет introspection (__schema/__type)
      • Лимит глубины и "комплексности" запроса
      • Persisted Query режим
      • Эвристические запреты по полям/директивам/значениям
      • Rate-limit по идентификатору клиента (IP или заголовок)

    Прозрачно прокидывает тело дальше в приложение, если проверка успешна.
    """

    def __init__(
        self,
        app,
        config: Optional[InhibitorConfig] = None,
        *,
        identity_header: Optional[str] = "x-api-key",  # можно указать заголовок, по которому ограничивать
    ):
        self.app = app
        self.cfg = config or InhibitorConfig()
        self.limiter = _RateLimiter(self.cfg.rps_per_identity, self.cfg.burst_per_identity)
        self.identity_header = (identity_header or "").lower() if identity_header else None
        self.log = get_logger("genius_core.self_inhibitor.graphql")
        # Предкомпилируем регекспы
        self._deny_field_res = [re.compile(p) for p in self.cfg.deny_field_patterns]
        self._deny_dir_res = [re.compile(p) for p in self.cfg.deny_directive_patterns]
        self._deny_val_res = [re.compile(p) for p in self.cfg.value_deny_regexes]

    # --------- ASGI entrypoint ---------

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        if self.cfg.paths and path not in self.cfg.paths:
            return await self.app(scope, receive, send)

        method = scope.get("method", "GET").upper()
        client = scope.get("client", ("", 0))
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}

        identity = self._client_identity(headers, client)
        if not self.limiter.allow(identity):
            await self._reject(send, 429, "RATE_LIMITED", "rate limit exceeded", request_id=headers.get("x-request-id"))
            self._log_security("rate_limited", path=path, identity=identity)
            return

        # Поддержка GET с query в строке запроса
        if method == "GET":
            query_text = self._extract_query_from_querystring(scope)
            if query_text is None:
                return await self.app(scope, receive, send)
            # Преобразуем к псевдо-POST телу для унификации
            body_obj = {"query": query_text}
            body = json.dumps(body_obj).encode("utf-8")
            return await self._process_and_forward(scope, headers, body, send, identity)

        # POST: читаем тело полностью (с таймаутом)
        try:
            body = await asyncio.wait_for(self._read_body(receive), timeout=self.cfg.read_body_timeout_s)
        except asyncio.TimeoutError:
            await self._reject(send, 408, "REQUEST_TIMEOUT", "request body read timeout", request_id=headers.get("x-request-id"))
            self._log_security("read_timeout", path=path, identity=identity)
            return

        return await self._process_and_forward(scope, headers, body, send, identity)

    # --------- Основная логика ---------

    async def _process_and_forward(self, scope, headers: Mapping[str, str], body: bytes, send, identity: str):
        path = scope.get("path", "")

        # Размер тела
        if len(body) > (self.cfg.max_query_length + self.cfg.max_variables_bytes + 4096):
            await self._reject(send, 413, "PAYLOAD_TOO_LARGE", "request body too large", request_id=headers.get("x-request-id"))
            self._log_security("payload_too_large", path=path, identity=identity, size=len(body))
            return

        # Разбор JSON
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            await self._reject(send, 400, "BAD_REQUEST", "invalid JSON", request_id=headers.get("x-request-id"))
            self._log_security("invalid_json", path=path, identity=identity)
            return

        # Поддержка батчей
        if isinstance(payload, list):
            if len(payload) > self.cfg.max_batch_size:
                await self._reject(send, 400, "BATCH_TOO_LARGE", "batch size exceeded", request_id=headers.get("x-request-id"))
                self._log_security("batch_too_large", path=path, identity=identity, batch=len(payload))
                return
            for item in payload:
                if not await self._validate_single(item, headers, path, identity):
                    return  # уже отправлен reject
        else:
            if not await self._validate_single(payload, headers, path, identity):
                return  # уже отправлен reject

        # Если всё хорошо — прокидываем тело дальше (оборачиваем receive, чтобы отдать то же самое тело приложению)
        async def new_receive():
            # Один раз возвращаем тело, затем пустышки
            nonlocal body
            b, body = body, b""
            return {"type": "http.request", "body": b, "more_body": False}

        return await self.app(scope, new_receive, send)

    async def _validate_single(self, data: Dict[str, Any], headers: Mapping[str, str], path: str, identity: str) -> bool:
        query: Optional[str] = data.get("query")
        variables = data.get("variables") or {}
        op_name = data.get("operationName")
        extensions = data.get("extensions") or {}

        # Persisted Query режим
        if self.cfg.require_persisted:
            pq = (extensions or {}).get("persistedQuery") or {}
            if not isinstance(pq, dict) or "sha256Hash" not in pq:
                await self._reject_graphql("PERSISTED_QUERY_REQUIRED", "persisted query required", headers)
                self._log_security("pq_required", path=path, identity=identity)
                return False
            if (query and not self.cfg.allow_query_text_when_persisted):
                await self._reject_graphql("PERSISTED_QUERY_ONLY", "query text not allowed with persisted mode", headers)
                self._log_security("pq_text_disallowed", path=path, identity=identity)
                return False

        # Базовые лимиты размеров
        if query and len(query) > self.cfg.max_query_length:
            await self._reject_graphql("QUERY_TOO_LARGE", "query text too long", headers)
            self._log_security("query_too_large", path=path, identity=identity, qlen=len(query))
            return False

        try:
            variables_bytes = len(json.dumps(variables, ensure_ascii=False).encode("utf-8"))
        except Exception:
            await self._reject_graphql("VARIABLES_INVALID", "variables must be JSON-serializable", headers)
            self._log_security("vars_invalid", path=path, identity=identity)
            return False

        if variables_bytes > self.cfg.max_variables_bytes:
            await self._reject_graphql("VARIABLES_TOO_LARGE", "variables too large", headers)
            self._log_security("vars_too_large", path=path, identity=identity, vbytes=variables_bytes)
            return False

        # Эвристика «опасных значений» (SSRF/секреты/SQL-инъекции)
        if self.cfg.scan_values_for_malware and self._contains_malicious_value(variables):
            await self._reject_graphql("MALICIOUS_VALUE", "variables contain disallowed patterns", headers)
            self._log_security("malicious_values", path=path, identity=identity)
            return False

        # Если нет текста запроса (Persisted/GET без query) — пропускаем дальнейшие AST-чекы
        if not query or not isinstance(query, str):
            return True

        # Если нет graphql-core — делаем только эвристические проверки текста
        if not _HAS_GRAPHQL:
            if self.cfg.block_introspection and ("__schema" in query or "__type" in query or "IntrospectionQuery" in query):
                await self._reject_graphql("INTROSPECTION_BLOCKED", "introspection is disabled", headers)
                self._log_security("introspection_blocked_no_ast", path=path, identity=identity)
                return False
            # Минимальный запрет директив по текстовому совпадению
            for rex in self._deny_dir_res:
                if rex.search(query):
                    await self._reject_graphql("DIRECTIVE_BLOCKED", "directive not allowed", headers)
                    self._log_security("directive_blocked_no_ast", path=path, identity=identity, directive=rex.pattern)
                    return False
            return True

        # С AST-проверками
        try:
            doc: DocumentNode = parse(query)
        except Exception:
            await self._reject_graphql("SYNTAX_ERROR", "invalid GraphQL syntax", headers)
            self._log_security("syntax_error", path=path, identity=identity)
            return False

        # Тип операции
        op_type = self._detect_operation_type(doc, op_name)
        if not self._is_operation_allowed(op_type):
            await self._reject_graphql("OPERATION_NOT_ALLOWED", f"{op_type} not allowed", headers)
            self._log_security("op_disallowed", path=path, identity=identity, op=op_type)
            return False

        # Интроспекция
        if self.cfg.block_introspection and self._contains_introspection(doc):
            await self._reject_graphql("INTROSPECTION_BLOCKED", "introspection is disabled", headers)
            self._log_security("introspection_blocked", path=path, identity=identity)
            return False

        # Запрещённые поля/директивы
        bad_field = self._find_denied_field(doc)
        if bad_field:
            await self._reject_graphql("FIELD_BLOCKED", f"field '{bad_field}' not allowed", headers)
            self._log_security("field_blocked", path=path, identity=identity, field=bad_field)
            return False
        bad_dir = self._find_denied_directive(query)  # директивы проще искать текстово
        if bad_dir:
            await self._reject_graphql("DIRECTIVE_BLOCKED", f"directive '{bad_dir}' not allowed", headers)
            self._log_security("directive_blocked", path=path, identity=identity, directive=bad_dir)
            return False

        # Глубина/комплексность
        depth = self._max_depth(doc, op_name)
        if depth > self.cfg.max_depth:
            await self._reject_graphql("DEPTH_EXCEEDED", f"max depth {self.cfg.max_depth} exceeded", headers)
            self._log_security("depth_exceeded", path=path, identity=identity, depth=depth)
            return False

        complexity = self._complexity(doc, variables)
        if complexity > self.cfg.max_complexity:
            await self._reject_graphql("COMPLEXITY_EXCEEDED", f"max complexity {self.cfg.max_complexity} exceeded", headers)
            self._log_security("complexity_exceeded", path=path, identity=identity, complexity=complexity)
            return False

        return True

    # --------- Вспомогательное ---------

    def _client_identity(self, headers: Mapping[str, str], client: Tuple[str, int]) -> str:
        if self.identity_header and headers.get(self.identity_header):
            return f"hdr:{self.identity_header}:{headers.get(self.identity_header)}"
        ip = client[0] or headers.get("x-forwarded-for", "").split(",")[0].strip()
        return f"ip:{ip or 'unknown'}"

    async def _read_body(self, receive) -> bytes:
        chunks: List[bytes] = []
        more = True
        while more:
            msg = await receive()
            if msg["type"] != "http.request":
                continue
            body = msg.get("body", b"") or b""
            if body:
                chunks.append(body)
            more = msg.get("more_body", False)
        return b"".join(chunks)

    def _extract_query_from_querystring(self, scope) -> Optional[str]:
        raw = scope.get("query_string", b"") or b""
        if not raw:
            return None
        try:
            qs = raw.decode("utf-8", errors="ignore")
            for part in qs.split("&"):
                if part.startswith("query="):
                    from urllib.parse import unquote_plus
                    return unquote_plus(part[len("query="):])
        except Exception:
            return None
        return None

    async def _reject(self, send, status: int, code: str, msg: str, request_id: Optional[str] = None):
        payload = {
            "errors": [{
                "message": "Forbidden",
                "extensions": {
                    "code": code,
                    **({"reason": msg} if self.cfg.include_reasons_in_errors else {}),
                }
            }]
        }
        body = json.dumps(payload).encode("utf-8")
        headers = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        if request_id:
            headers.append((b"x-request-id", request_id.encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def _reject_graphql(self, code: str, msg: str, headers: Mapping[str, str]):
        await self._reject(lambda m: None, 400, code, msg, request_id=headers.get("x-request-id"))  # type: ignore

    def _log_security(self, event: str, **fields: Any) -> None:
        try:
            self.log.warning(event, extra=log_extra(**fields))
        except Exception:
            pass

    # --------- AST-аналитика ---------

    def _is_operation_allowed(self, op_type: str) -> bool:
        op_type = (op_type or "query").lower()
        return (op_type == "query" and self.cfg.allow_query) or \
               (op_type == "mutation" and self.cfg.allow_mutation) or \
               (op_type == "subscription" and self.cfg.allow_subscription)

    def _detect_operation_type(self, doc: DocumentNode, op_name: Optional[str]) -> str:
        # Находим первую операцию или по имени
        for defn in getattr(doc, "definitions", []):
            if isinstance(defn, OperationDefinitionNode):
                if not op_name or defn.name and defn.name.value == op_name:
                    return str(defn.operation.value if hasattr(defn.operation, "value") else defn.operation).lower()
        return "query"

    def _contains_introspection(self, doc: DocumentNode) -> bool:
        for defn in getattr(doc, "definitions", []):
            sels = getattr(defn, "selection_set", None)
            if not sels:
                continue
            if self._selection_contains_introspection(sels):
                return True
        return False

    def _selection_contains_introspection(self, sel: SelectionSetNode) -> bool:
        for s in getattr(sel, "selections", []):
            if isinstance(s, FieldNode):
                name = getattr(s.name, "value", "")
                if name in ("__schema", "__type"):
                    return True
                if s.selection_set and self._selection_contains_introspection(s.selection_set):
                    return True
            elif isinstance(s, (InlineFragmentNode, FragmentSpreadNode)):
                sub = getattr(s, "selection_set", None)
                if sub and self._selection_contains_introspection(sub):
                    return True
        return False

    def _find_denied_field(self, doc: DocumentNode) -> Optional[str]:
        for defn in getattr(doc, "definitions", []):
            sels = getattr(defn, "selection_set", None)
            if not sels:
                continue
            f = self._selection_denied_field(sels)
            if f:
                return f
        return None

    def _selection_denied_field(self, sel: SelectionSetNode) -> Optional[str]:
        for s in getattr(sel, "selections", []):
            if isinstance(s, FieldNode):
                name = getattr(s.name, "value", "")
                for rex in self._deny_field_res:
                    if rex.search(name):
                        return name
                if s.selection_set:
                    f = self._selection_denied_field(s.selection_set)
                    if f:
                        return f
            elif isinstance(s, (InlineFragmentNode, FragmentSpreadNode)):
                sub = getattr(s, "selection_set", None)
                if sub:
                    f = self._selection_denied_field(sub)
                    if f:
                        return f
        return None

    def _find_denied_directive(self, query_text: str) -> Optional[str]:
        for rex in self._deny_dir_res:
            m = rex.search(query_text)
            if m:
                # Возвращаем имя директивы (без @)
                name = m.group(0).lstrip("@")
                return name
        return None

    def _max_depth(self, doc: DocumentNode, op_name: Optional[str]) -> int:
        max_depth = 0

        def walk_sel(sel: SelectionSetNode, depth: int) -> None:
            nonlocal max_depth
            max_depth = max(max_depth, depth)
            for s in getattr(sel, "selections", []):
                if isinstance(s, FieldNode) and s.selection_set:
                    walk_sel(s.selection_set, depth + 1)
                elif isinstance(s, InlineFragmentNode) and s.selection_set:
                    walk_sel(s.selection_set, depth + 1)
                # FragmentSpreadNode требует разрешения по фрагментам — упрощаем: считаем +1
                elif isinstance(s, FragmentSpreadNode):
                    max_depth = max(max_depth, depth + 1)

        for defn in getattr(doc, "definitions", []):
            if isinstance(defn, OperationDefinitionNode):
                if op_name and defn.name and defn.name.value != op_name:
                    continue
                if defn.selection_set:
                    walk_sel(defn.selection_set, 1)
        return max_depth

    def _complexity(self, doc: DocumentNode, variables: Mapping[str, Any]) -> int:
        """
        Простейшая эвристика комплексности:
          • базовая стоимость поля = 1
          • аргументы first/last/limit/first:n увеличивают стоимость * n (по возможности)
          • суммируем по дереву
        """
        def arg_multiplier(args: List[Any]) -> int:
            mul = 1
            names = {"first", "last", "limit", "take", "top"}
            for a in args or []:
                name = getattr(getattr(a, "name", None), "value", None)
                if name in names:
                    val_node = getattr(a, "value", None)
                    v = None
                    # Числовой литерал
                    if hasattr(val_node, "value") and isinstance(getattr(val_node, "value"), (int, float)):
                        v = int(getattr(val_node, "value"))
                    # Переменная
                    elif getattr(val_node, "kind", None) == "variable":
                        var_name = getattr(getattr(val_node, "name", None), "value", None)
                        v = int(variables.get(var_name)) if var_name in variables and str(variables.get(var_name)).isdigit() else None
                    if isinstance(v, int) and v > 0:
                        mul *= max(1, min(v, 10_000))  # кап на случай злоупотреблений
            return mul

        cost = 0

        def walk_sel(sel: SelectionSetNode) -> int:
            nonlocal cost
            subtotal = 0
            for s in getattr(sel, "selections", []):
                if isinstance(s, FieldNode):
                    c = 1 * arg_multiplier(getattr(s, "arguments", []) or [])
                    if s.selection_set:
                        c += walk_sel(s.selection_set)
                    subtotal += c
                elif isinstance(s, InlineFragmentNode) and s.selection_set:
                    subtotal += walk_sel(s.selection_set)
                elif isinstance(s, FragmentSpreadNode):
                    subtotal += 1
            return subtotal

        for defn in getattr(doc, "definitions", []):
            if isinstance(defn, OperationDefinitionNode) and defn.selection_set:
                cost += walk_sel(defn.selection_set)

        # Грубый кап, чтобы избежать int overflow
        return int(min(cost, 1_000_000_000))

    def _contains_malicious_value(self, variables: Any) -> bool:
        # Обходит JSON-совместимые структуры
        stack = [variables]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                for v in x.values():
                    stack.append(v)
            elif isinstance(x, (list, tuple)):
                stack.extend(x)
            else:
                if isinstance(x, (str, bytes)):
                    s = x.decode("utf-8", errors="ignore") if isinstance(x, bytes) else x
                    for rex in self._deny_val_res:
                        if rex.search(s):
                            return True
        return False
