# -*- coding: utf-8 -*-
"""
mythos-core/mythos/dialogue/runtime.py

Промышленный рантайм диалогов для Mythos Core.
Особенности:
- Загрузка dialogue-pack (dict или путь к YAML/JSON)
- Контекст разговора, слоты и переменные
- NLU на правилах/regex из пакета + простая маршрутизация интентов
- Policy engine: rule-first, fallback, условия и действия (включая вызовы инструментов)
- Инструменты (function calling) с валидацией простой JSON-схемы и таймаутами
- RAG-поиск по файловой базе (гибкий, на stdlib; top-k)
- Модерация через провайдер-плагин (по умолчанию no-op)
- Рендеринг ответов (A/B-варианты, placeholders из context/slots/results)
- Память (короткая и долгая) с TTL и фильтрацией
- Наблюдаемость: структурные логи, метрики (счётчики/тайминги в памяти)
- Детерминированность для тестов (MYTHOS_DETERMINISTIC=1)

Зависимости: только стандартная библиотека Python 3.10+.
Лицензия: proprietary (Aethernova / Mythos Core)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import yaml  # не обязателен: если нет, используйте JSON
except Exception:
    yaml = None  # type: ignore[assignment]

# ------------------------------
# Конфигурация и утилиты
# ------------------------------

def _env_truth(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")

def _now_ms() -> int:
    return int(time.time() * 1000)

def _safe_get(d: Mapping[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return default
        cur = cur[part]
    return cur

# ------------------------------
# Телеметрия (в памяти)
# ------------------------------

@dataclass
class Metrics:
    counters: Dict[str, int] = field(default_factory=dict)
    timers: Dict[str, List[float]] = field(default_factory=dict)

    def inc(self, name: str, n: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + n

    def observe(self, name: str, seconds: float) -> None:
        self.timers.setdefault(name, []).append(seconds)

# ------------------------------
# Контекст диалога и ответ
# ------------------------------

@dataclass
class DialogueContext:
    user_id: str
    locale: str = "ru-RU"
    timezone: str = "UTC"
    slots: Dict[str, Any] = field(default_factory=dict)
    vars: Dict[str, Any] = field(default_factory=dict)
    moderation: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)  # для простых политик
    rag_hits: List[Dict[str, Any]] = field(default_factory=list)
    request_id: str = field(default_factory=lambda: os.urandom(8).hex())

@dataclass
class DialogueResponse:
    text: str
    response_id: Optional[str] = None
    citations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

# ------------------------------
# Память (короткая/долгая)
# ------------------------------

class MemoryStore:
    def __init__(self) -> None:
        self._short: Dict[str, List[Dict[str, Any]]] = {}
        self._long: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def remember_short(self, user_id: str, record: Dict[str, Any], keep_turns: int = 10) -> None:
        arr = self._short.setdefault(user_id, [])
        arr.append(record)
        if len(arr) > max(1, keep_turns):
            del arr[0 : len(arr) - keep_turns]

    def recall_short(self, user_id: str) -> List[Dict[str, Any]]:
        return list(self._short.get(user_id, []))

    def remember_long(self, user_id: str, key: str, value: Any, ttl_days: int = 30) -> None:
        usr = self._long.setdefault(user_id, {})
        usr[key] = {"value": value, "expires_at_ms": _now_ms() + ttl_days * 24 * 3600 * 1000}

    def recall_long(self, user_id: str, key: str) -> Optional[Any]:
        usr = self._long.get(user_id, {})
        item = usr.get(key)
        if not item:
            return None
        if item["expires_at_ms"] < _now_ms():
            del usr[key]
            return None
        return item["value"]

# ------------------------------
# Модерация (плагин)
# ------------------------------

class ModerationProvider:
    def __init__(self, cfg: Mapping[str, Any]) -> None:
        self.enabled = bool(_safe_get(cfg, "moderation.enabled", False))
        self.thresholds = _safe_get(cfg, "moderation.thresholds", {}) or {}

    async def check(self, text: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"blocked": False, "flags": {}}
        # Заглушка: просто всегда позволяет. Интегрируйте модель по необходимости.
        return {"blocked": False, "flags": {}}

# ------------------------------
# RAG (простой файловый ретривер)
# ------------------------------

class SimpleRAG:
    def __init__(self, cfg: Mapping[str, Any]) -> None:
        r = _safe_get(cfg, "rag", {}) or {}
        self.enabled = bool(r.get("enabled", False))
        self.sources = r.get("sources", [])
        self.top_k = int(_safe_get(r, "retriever.top_k", 5) or 5)
        self.min_score = float(_safe_get(r, "retriever.min_score", 0.35) or 0.35)

    def _iter_docs(self) -> Iterable[Tuple[str, str]]:
        for src in self.sources:
            if src.get("kind") != "fs":
                continue
            base = Path(src["path"])
            if not base.exists():
                continue
            for p in base.rglob("*"):
                if p.is_file() and (not src.get("format") or p.suffix.lower().lstrip(".") == src["format"]):
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore")
                        yield str(p), text
                    except Exception:
                        continue

    def search(self, query: str, top_k: Optional[int] = None) -> List[Dict[str, Any]]:
        if not self.enabled or not query.strip():
            return []
        q = query.lower()
        hits: List[Tuple[float, str, str]] = []
        for path, text in self._iter_docs():
            t = text.lower()
            # очень простой скоринг: сумма вхождений + бонус за заголовки
            score = t.count(q)
            if score <= 0:
                continue
            if "# " in t or "## " in t:
                score += 0.5
            hits.append((float(score), path, text[:1000]))
        hits.sort(key=lambda x: x[0], reverse=True)
        out: List[Dict[str, Any]] = []
        K = top_k or self.top_k
        for s, p, snippet in hits[:K]:
            if s < self.min_score:
                continue
            out.append({"path": p, "score": s, "snippet": snippet})
        return out

# ------------------------------
# Инструменты (function calling)
# ------------------------------

class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, Callable[..., Awaitable[Any]]] = {}
        self._schemas: Dict[str, Mapping[str, Any]] = {}

    def register(self, name: str, func: Callable[..., Awaitable[Any]], schema: Optional[Mapping[str, Any]] = None) -> None:
        self._tools[name] = func
        if schema:
            self._schemas[name] = schema

    def has(self, name: str) -> bool:
        return name in self._tools

    async def call(self, name: str, args: Mapping[str, Any], timeout_s: float = 10.0) -> Any:
        if name not in self._tools:
            raise RuntimeError(f"Tool not registered: {name}")
        schema = self._schemas.get(name)
        if schema:
            _validate_schema(args, schema)
        coro = self._tools[name](**args)  # type: ignore[call-arg]
        return await asyncio.wait_for(coro, timeout=timeout_s)

def _validate_schema(data: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    if schema.get("type") != "object":
        return
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    for r in required:
        if r not in data:
            raise ValueError(f"Missing required arg: {r}")
    for k, v in data.items():
        desc = props.get(k)
        if not desc:
            # Запрещаем произвольные поля, если задан schema.properties
            if props:
                raise ValueError(f"Unexpected arg: {k}")
            continue
        t = desc.get("type")
        if t == "string" and not isinstance(v, str):
            raise ValueError(f"Arg {k} must be string")
        if t == "integer" and not isinstance(v, int):
            raise ValueError(f"Arg {k} must be integer")
        if t == "number" and not isinstance(v, (int, float)):
            raise ValueError(f"Arg {k} must be number")
        if t == "boolean" and not isinstance(v, bool):
            raise ValueError(f"Arg {k} must be boolean")
        pattern = desc.get("pattern")
        if isinstance(v, str) and pattern and not re.compile(pattern).match(v):
            raise ValueError(f"Arg {k} does not match pattern")

# ------------------------------
# NLU (простой, на правилах)
# ------------------------------

class SimpleNLU:
    def __init__(self, pack: Mapping[str, Any]) -> None:
        self.intents: List[Tuple[str, List[re.Pattern[str]]]] = []
        self.entities: Dict[str, List[re.Pattern[str]]] = {}
        for it in _safe_get(pack, "nlu.intents", []) or []:
            pats = [re.compile(_to_regex(p)) for p in it.get("examples", [])]
            self.intents.append((it["name"], pats))
        for ent in _safe_get(pack, "nlu.entities", []) or []:
            self.entities[ent["name"]] = [re.compile(_to_regex(p)) for p in ent.get("patterns", [])]

    def parse(self, text: str) -> Dict[str, Any]:
        s = text.strip()
        low = s.lower()
        best_intent = None
        for name, patterns in self.intents:
            for rx in patterns:
                if rx.search(low):
                    best_intent = name
                    break
            if best_intent:
                break
        entities: Dict[str, str] = {}
        for name, patterns in self.entities.items():
            for rx in patterns:
                m = rx.search(s)
                if m:
                    entities[name] = m.group(0)
                    break
        return {"intent": best_intent or "fallback", "entities": entities}

def _to_regex(sample: str) -> str:
    # упрощённая нормализация примеров
    sample = sample.strip()
    sample = re.sub(r"\{[a-zA-Z0-9_]+\}", "(.+)", sample)
    if len(sample) < 2:
        return re.escape(sample)
    return r"(?i)\b" + re.escape(sample).replace("\\(\\.\\+\\)", "(.+)") + r"\b"

# ------------------------------
# Политики диалога
# ------------------------------

class PolicyEngine:
    def __init__(self, pack: Mapping[str, Any]) -> None:
        pol = _safe_get(pack, "dialogue.policy", {}) or {}
        self.rules = pol.get("rules", [])
        self.fallback = pol.get("fallback", {"respond": "resp.fallback", "max_retries": 0})

    def decide(self, intent: str, ctx: DialogueContext) -> Dict[str, Any]:
        for r in self.rules:
            cond = r.get("if", {})
            # intent match
            if "intent" in cond and cond["intent"] != intent:
                continue
            # custom condition via context vars (минимальная поддержка)
            if "condition" in cond:
                if not _eval_condition(cond["condition"], ctx):
                    continue
            # matched
            return {
                "respond": r.get("then", {}).get("respond"),
                "actions": r.get("then", {}).get("actions", []),
                "end": r.get("then", {}).get("end_conversation", False),
            }
        return {"respond": self.fallback.get("respond"), "actions": [], "end": False}

def _eval_condition(expr: str, ctx: DialogueContext) -> bool:
    # очень ограниченный eval: доступ к ctx.vars/slots/moderation
    safe_env = {
        "slots": ctx.slots,
        "vars": ctx.vars,
        "moderation": ctx.moderation,
        "len": len,
        "any": any,
        "all": all,
    }
    try:
        return bool(eval(expr, {"__builtins__": {}}, safe_env))
    except Exception:
        return False

# ------------------------------
# Рендеринг ответов
# ------------------------------

class TemplateRenderer:
    def __init__(self, pack: Mapping[str, Any]) -> None:
        rnd_seed = int(os.getenv("MYTHOS_RENDER_SEED", "0") or "0")
        self.rand = random.Random(0 if _env_truth("MYTHOS_DETERMINISTIC", False) else rnd_seed or time.time_ns())
        self.responses = pack.get("responses", {}) or {}
        self.hallucination_guard = bool(_safe_get(pack, "rag.hallucination_guard.require_quote_for_facts", False))
        self.unknown_text = _safe_get(pack, "rag.hallucination_guard.unknown_answer_text", "I cannot verify this.")

    def render(self, resp_id: str, ctx: DialogueContext, extra: Mapping[str, Any] | None = None) -> DialogueResponse:
        spec = self.responses.get(resp_id) or {}
        loc = _safe_get(spec, "locale", {}) or {}
        lang = ctx.locale or "ru-RU"
        entry = loc.get(lang) or loc.get("en-US") or {}
        variants = entry.get("variants", [])
        if not variants:
            return DialogueResponse(text=self.unknown_text, response_id=resp_id)
        variant = self._choose_variant(variants)
        placeholders: Dict[str, Any] = {}
        placeholders.update(ctx.vars)
        placeholders.update(ctx.slots)
        if extra:
            placeholders.update(extra)
        text = _format_safe(variant.get("text", ""), placeholders)
        citations: List[str] = []
        if self.hallucination_guard and "{" in text and not ctx.rag_hits:
            # примитивная защита: если требуем факты и нет цитат, возвращаем unknown
            text = self.unknown_text
        if ctx.rag_hits:
            for h in ctx.rag_hits[:3]:
                citations.append(h.get("path", ""))
        return DialogueResponse(text=text, response_id=resp_id, citations=citations, metadata={"variant": variant})

    def _choose_variant(self, variants: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
        if len(variants) == 1:
            return variants[0]
        weights = [float(v.get("weight", 1)) for v in variants]
        total = sum(weights) or 1.0
        r = self.rand.random() * total
        acc = 0.0
        for v, w in zip(variants, weights):
            acc += w
            if r <= acc:
                return v
        return variants[-1]

def _format_safe(template: str, values: Mapping[str, Any]) -> str:
    class _Safe(dict):
        def __missing__(self, key: str) -> str:
            return "{" + key + "}"
    try:
        return template.format_map(_Safe(values))
    except Exception:
        return template

# ------------------------------
# Главный рантайм
# ------------------------------

class DialogueRuntime:
    def __init__(
        self,
        dialogue_pack: Mapping[str, Any] | str,
        tools: Optional[ToolRegistry] = None,
        memory: Optional[MemoryStore] = None,
        metrics: Optional[Metrics] = None,
    ) -> None:
        self.pack = self._load_pack(dialogue_pack)
        self.metrics = metrics or Metrics()
        self.tools = tools or ToolRegistry()
        self.memory = memory or MemoryStore()
        self.nlu = SimpleNLU(self.pack)
        self.policy = PolicyEngine(self.pack)
        self.renderer = TemplateRenderer(self.pack)
        self.moderation = ModerationProvider(self.pack)
        self.rag = SimpleRAG(self.pack)
        self.default_locale = _safe_get(self.pack, "runtime.default_locale", "ru-RU")
        logging.basicConfig(level=os.getenv("MYTHOS_LOG_LEVEL", "INFO").upper(), format="%(message)s")

    # --------- публичный API ---------

    async def handle_turn(self, user_id: str, text: str, *, locale: Optional[str] = None) -> DialogueResponse:
        t0 = time.perf_counter()
        ctx = DialogueContext(user_id=user_id, locale=locale or self.default_locale)
        ctx.history = self.memory.recall_short(user_id)

        # Модерация
        mod = await self.moderation.check(text)
        ctx.moderation = mod
        if mod.get("blocked"):
            self.metrics.inc("turn_blocked")
            return self.renderer.render("resp.moderation_block", ctx)

        # NLU
        parsed = self.nlu.parse(text)
        intent = parsed["intent"]
        entities = parsed["entities"]
        # Заполняем слоты (простая логика)
        for name, value in entities.items():
            ctx.slots[name] = value

        # Применяем правила памяти из пакета (долгая память)
        self._memory_ingest(ctx, intent)

        # Политика диалога
        decision = self.policy.decide(intent, ctx)

        # Вызов инструментов (если прописаны)
        actions = decision.get("actions", []) or []
        for act in actions:
            await self._execute_action(act, ctx)

        # Если RAG есть и в ctx.slots.topic присутствует — попытаемся найти
        topic = ctx.slots.get("topic")
        if topic and self.rag.enabled and intent in ("retrieve_doc",):
            ctx.rag_hits = self.rag.search(str(topic), top_k=None)

        # Рендеринг ответа
        resp_id = decision.get("respond") or "resp.fallback"
        resp = self.renderer.render(resp_id, ctx, extra={"count": len(ctx.rag_hits), "topic": topic or ""})

        # Обновляем короткую память
        self.memory.remember_short(user_id, {
            "ts": _now_ms(), "text": text, "intent": intent, "slots": dict(ctx.slots), "resp_id": resp_id
        }, keep_turns=int(_safe_get(self.pack, "testing.deterministic.keep_turns", 10) or 10))

        # Метрики/логи
        self.metrics.inc(f"turn_intent_{intent}")
        self.metrics.observe("turn_latency", time.perf_counter() - t0)
        logging.info(
            json.dumps({
                "event": "turn",
                "user_id": user_id,
                "intent": intent,
                "resp_id": resp_id,
                "request_id": ctx.request_id,
                "latency_ms": int((time.perf_counter() - t0) * 1000),
                "tool_calls": ctx.vars.get("_tool_calls", []),
                "moderation_flags": mod.get("flags", {}),
                "rag_citations_count": len(resp.citations),
            }, ensure_ascii=False)
        )
        return resp

    # --------- внутреннее ---------

    def _load_pack(self, dp: Mapping[str, Any] | str) -> Mapping[str, Any]:
        if isinstance(dp, Mapping):
            return dp
        p = Path(dp)
        if not p.exists():
            raise FileNotFoundError(dp)
        if p.suffix.lower() in {".yaml", ".yml"}:
            if not yaml:
                raise RuntimeError("PyYAML не установлен, используйте JSON или передайте dict")
            with p.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)

    async def _execute_action(self, action: Any, ctx: DialogueContext) -> None:
        # Поддержка формата: строка с именем инструмента или dict {call,args,store_result_as,on_error}
        if isinstance(action, str):
            if not self.tools.has(action):
                return
            res = await self.tools.call(action, {}, timeout_s=10.0)
            ctx.vars[action] = res
            calls = ctx.vars.setdefault("_tool_calls", [])
            calls.append({"name": action, "ok": True})
            return
        if isinstance(action, Mapping):
            name = action.get("call")
            if not name or not self.tools.has(name):
                return
            args_tpl = action.get("args", {}) or {}
            args = _render_args_from_context(args_tpl, ctx)
            store_as = action.get("store_result_as")
            try:
                res = await self.tools.call(name, args, timeout_s=float(action.get("timeout", 10.0)))
                if store_as:
                    ctx.vars[store_as] = res
                calls = ctx.vars.setdefault("_tool_calls", [])
                calls.append({"name": name, "ok": True})
            except Exception as ex:
                calls = ctx.vars.setdefault("_tool_calls", [])
                calls.append({"name": name, "ok": False, "error": str(ex)})
                on_err = action.get("on_error", {})
                # on_error может указывать respond для немедленного fallback-а (но здесь лишь отмечаем)
                ctx.vars.setdefault("_errors", []).append({"tool": name, "error": str(ex)})
        # игнорируем иные типы

    def _memory_ingest(self, ctx: DialogueContext, intent: str) -> None:
        lm = _safe_get(self.pack, "memory.long_term", {}) or {}
        if not lm.get("enabled"):
            return
        for sel in lm.get("selectors", []) or []:
            ints = sel.get("when_intent_in", [])
            if ints and intent not in ints:
                continue
            for spec in sel.get("extract", []) or []:
                key = spec.get("key")
                src = spec.get("from", "")
                ttl = int(spec.get("ttl_days", 30))
                # поддержка only slots.*/vars.*
                if src.startswith("slots."):
                    v = ctx.slots.get(src.split(".", 1)[1])
                elif src.startswith("vars."):
                    v = ctx.vars.get(src.split(".", 1)[1])
                else:
                    v = None
                if key and v is not None:
                    self.memory.remember_long(ctx.user_id, key, v, ttl_days=ttl)

# ------------------------------
# Контекстная подстановка аргументов инструментов
# ------------------------------

def _render_args_from_context(tmpl: Mapping[str, Any], ctx: DialogueContext) -> Dict[str, Any]:
    def render_val(v: Any) -> Any:
        if isinstance(v, str) and v.startswith("{") and v.endswith("}"):
            k = v[1:-1]
            if k.startswith("slots."):
                return ctx.slots.get(k.split(".", 1)[1])
            if k.startswith("vars."):
                return ctx.vars.get(k.split(".", 1)[1])
            return v
        if isinstance(v, Mapping):
            return {kk: render_val(vv) for kk, vv in v.items()}
        if isinstance(v, list):
            return [render_val(x) for x in v]
        return v
    return {k: render_val(v) for k, v in tmpl.items()}

# ------------------------------
# Пример регистрации инструментов (асинхронных)
# ------------------------------

async def _demo_web_search(query: str, top_k: int = 5) -> Dict[str, Any]:
    # Заглушка; интегрируйте ваш поиск
    return {"query": query, "hits": [], "top_k": top_k}

def build_default_tool_registry(pack: Mapping[str, Any]) -> ToolRegistry:
    tr = ToolRegistry()
    for tool in _safe_get(pack, "tools.definitions", []) or []:
        name = tool["name"]
        schema = tool.get("schema", {})
        # привязываем демо-функцию, реальная интеграция — в проде
        func = _demo_web_search if name == "web_search" else _async_noop
        tr.register(name, func, schema=schema)
    return tr

async def _async_noop(**kwargs: Any) -> Dict[str, Any]:
    return {"ok": True, "args": kwargs}

# ------------------------------
# Пример использования (документирование)
# ------------------------------
"""
from mythos.dialogue.runtime import DialogueRuntime, build_default_tool_registry

pack_path = "mythos-core/configs/templates/dialogue_pack.example.yaml"
runtime = DialogueRuntime(pack_path, tools=build_default_tool_registry(runtime.pack))

resp = asyncio.run(runtime.handle_turn("user-1", "привет"))
print(resp.text)
"""

# Конец файла
