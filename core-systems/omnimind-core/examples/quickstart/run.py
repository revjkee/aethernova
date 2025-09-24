# -*- coding: utf-8 -*-
"""
OmniMind Core — Quickstart CLI

Подкоманды:
  prompt-preview         — рендер промпта (ChatML) и текстовый превью
  embed                  — получить эмбеддинги для строк
  plan-direct            — синхронное планирование через LLM (без очереди)
  queue-publish-plan     — отправить plan.request в Redis Streams
  worker-planner         — запустить воркер-планировщик
  http-memory-append     — тестовая запись в Memory API
  http-memory-query      — тестовый поиск/list в Memory API

Зависимости:
- Базовые модули OmniMind Core: omnimind.nlp.prompts, omnimind.memory.embeddings,
  omnimind.adapters.queue.redis_queue, omnimind.workers.planner_worker.
- Опционально: httpx (для LLM и HTTP-тестов), redis.asyncio (для очереди).

ENV (ключевые, см. соответствующие модули для полного перечня):
- OPENAI_API_KEY / ANTHROPIC_API_KEY и т.д.
- REDIS_URL, PLAN_IN_STREAM, PLAN_GROUP, PLAN_CONSUMER, PLAN_OUT_STREAM
- EMBEDDINGS_PROVIDER, OPENAI_EMBEDDING_MODEL и т.д.
- LOG_LEVEL (DEBUG|INFO|WARNING|ERROR)

Примеры:
  python examples/quickstart/run.py prompt-preview --id summarize --locale ru --var text="Тест" --var style=деловой
  python examples/quickstart/run.py embed "hello world" "добрый день"
  python examples/quickstart/run.py plan-direct --goal "Собрать MVP" --locale ru
  python examples/quickstart/run.py queue-publish-plan --goal "Собрать MVP" --request-id req-123
  python examples/quickstart/run.py worker-planner
  python examples/quickstart/run.py http-memory-append --url http://localhost:8080 --agent-id demo --type SEMANTIC --json '{"note":"hello"}'
  python examples/quickstart/run.py http-memory-query --url http://localhost:8080 --agent-id demo
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# ---------- Локальные импорты (мягкие) ----------

# Промпты
try:
    from omnimind.nlp.prompts import get_default_registry, build_chatml, preview_text
except Exception as e:
    get_default_registry = build_chatml = preview_text = None  # type: ignore

# Эмбеддинги
try:
    from omnimind.memory.embeddings import EmbeddingSettings, embed_sync, get_embeddings_service
except Exception as e:
    EmbeddingSettings = None  # type: ignore
    embed_sync = get_embeddings_service = None  # type: ignore

# Очередь и воркер
try:
    from omnimind.adapters.queue.redis_queue import RedisStreamQueue, RedisQueueSettings
except Exception:
    RedisStreamQueue = RedisQueueSettings = None  # type: ignore

try:
    from omnimind.workers.planner_worker import (
        PlannerWorker,
        PlannerSettings,
        LLMSettings,
    )
except Exception:
    PlannerWorker = PlannerSettings = LLMSettings = None  # type: ignore

# HTTP клиент (опционально)
try:
    import httpx  # type: ignore
except Exception:
    httpx = None  # type: ignore


# ---------- Утилиты ----------

def configure_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level if level in {"DEBUG", "INFO", "WARNING", "ERROR"} else "INFO",
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

def parse_kv(pairs: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for p in pairs:
        if "=" not in p:
            raise ValueError(f"Bad --var '{p}', expected key=value")
        k, v = p.split("=", 1)
        out[k] = v
    return out

def _require(cond: bool, msg: str):
    if not cond:
        print(msg, file=sys.stderr)
        sys.exit(2)

def _json_pretty(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


# ---------- Подкоманды ----------

async def cmd_prompt_preview(args: argparse.Namespace) -> None:
    _require(get_default_registry is not None, "Prompts module not available")
    reg = get_default_registry()
    vars_ = parse_kv(args.var or [])
    # удобные сокращения
    if "text" not in vars_ and args.text:
        vars_["text"] = args.text
    if "style" not in vars_ and args.style:
        vars_["style"] = args.style
    if "max_words" not in vars_ and args.max_words:
        vars_["max_words"] = str(args.max_words)

    chatml = build_chatml(registry=reg, id=args.id, vars=vars_, version=args.version, locale=args.locale)
    preview = preview_text(registry=reg, id=args.id, vars=vars_, version=args.version, locale=args.locale)

    print("# ChatML")
    print(_json_pretty(chatml))
    print("\n# Preview\n")
    print(preview)

async def cmd_embed(args: argparse.Namespace) -> None:
    _require(EmbeddingSettings is not None, "Embeddings module not available")
    texts = args.texts
    if not texts:
        print("No texts provided", file=sys.stderr)
        sys.exit(2)
    settings = EmbeddingSettings()  # конфигурация через ENV
    # Асинхронный путь — предпочтительно
    svc = await get_embeddings_service(settings)  # type: ignore
    res = await svc.embed_texts(texts)
    out = [{"dim": r.dim, "model": r.model, "vector_head": r.vector[:8]} for r in res]
    print(_json_pretty(out))

async def cmd_plan_direct(args: argparse.Namespace) -> None:
    _require(get_default_registry is not None, "Prompts module not available")
    _require(LLMSettings is not None and PlannerSettings is not None and PlannerWorker is not None, "Planner modules not available")
    _require(httpx is not None, "httpx is required for LLM calls")

    from omnimind.workers.planner_worker import LLMClient  # локальный клиент

    reg = get_default_registry()
    lcfg = LLMSettings()
    pcfg = PlannerSettings()

    messages = build_chatml(
        registry=reg,
        id=pcfg.prompt_id,
        version=pcfg.prompt_version,
        locale=(args.locale or pcfg.default_locale),
        vars={
            "goal": args.goal,
            "constraints": args.constraints or "—",
            "context": args.context or "—",
        },
    )

    client = LLMClient(lcfg)
    text, usage = await client.chat(messages)

    # попытка извлечь JSON-план
    def _extract_plan(s: str) -> List[Dict[str, Any]]:
        try:
            v = json.loads(s)
            if isinstance(v, list):
                return v
            if isinstance(v, dict) and isinstance(v.get("plan"), list):
                return v["plan"]
        except Exception:
            pass
        # поиск первого JSON массива в тексте
        start = s.find("[")
        while start != -1:
            depth = 0
            for i, ch in enumerate(s[start:], start=start):
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        chunk = s[start:i+1]
                        try:
                            v = json.loads(chunk)
                            if isinstance(v, list):
                                return v
                        except Exception:
                            break
            start = s.find("[", start + 1)
        raise RuntimeError("LLM output did not contain a JSON plan")

    plan = _extract_plan(text)

    print("# Raw LLM text\n")
    print(text)
    print("\n# Parsed plan\n")
    print(_json_pretty(plan))
    print("\n# Usage\n")
    print(_json_pretty(usage))

async def cmd_queue_publish_plan(args: argparse.Namespace) -> None:
    _require(RedisQueueSettings is not None and RedisStreamQueue is not None, "Redis queue modules not available")
    qcfg = RedisQueueSettings()
    # Переопределим поток назначения из ENV/настроек планировщика, если нужно
    stream = os.getenv("PLAN_IN_STREAM", qcfg.stream)
    q = RedisStreamQueue(qcfg)
    await q.start()
    try:
        payload = {
            "type": "plan.request",
            "request_id": args.request_id or f"req-{int(time.time())}",
            "goal": args.goal,
            "constraints": args.constraints,
            "context": args.context,
            "locale": args.locale,
            "response_stream": os.getenv("PLAN_OUT_STREAM"),  # опционально
        }
        msg_id = await q.enqueue(payload, message_key=payload["request_id"])
        print(_json_pretty({"stream": stream, "message_id": msg_id, "request_id": payload["request_id"]}))
    finally:
        await q.stop()

async def cmd_worker_planner(args: argparse.Namespace) -> None:
    _require(PlannerWorker is not None and PlannerSettings is not None and LLMSettings is not None and RedisQueueSettings is not None, "Planner/Queue modules not available")

    planner_cfg = PlannerSettings()
    queue_cfg = RedisQueueSettings(
        stream=planner_cfg.in_stream,
        group=planner_cfg.group,
        consumer=planner_cfg.consumer,
    )
    llm_cfg = LLMSettings()

    worker = PlannerWorker(planner_cfg, queue_cfg, llm_cfg)
    # Запуск до Ctrl+C
    try:
        await worker.run()
    except KeyboardInterrupt:
        pass

async def cmd_http_memory_append(args: argparse.Namespace) -> None:
    _require(httpx is not None, "httpx is required")
    url = args.url.rstrip("/") + "/v1/memory/append"
    headers = {"Content-Type": "application/json"}
    body = {
        "agent_id": args.agent_id,
        "type": args.type,
        "data": json.loads(args.json),
        "relevance": args.relevance,
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(url, headers=headers, json=body)
        print(_json_pretty({"status": r.status_code, "body": r.json() if r.headers.get("content-type","").startswith("application/json") else r.text}))

async def cmd_http_memory_query(args: argparse.Namespace) -> None:
    _require(httpx is not None, "httpx is required")
    url = args.url.rstrip("/") + "/v1/memory/query"
    headers = {"Content-Type": "application/json"}
    body: Dict[str, Any] = {"page": {"page_size": args.page_size}}
    if args.agent_id:
        body["agent_id"] = args.agent_id
    if args.text:
        body["text"] = args.text
    if args.types:
        body["types"] = args.types
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(url, headers=headers, json=body)
        print(_json_pretty({"status": r.status_code, "body": r.json() if r.headers.get("content-type","").startswith("application/json") else r.text}))


# ---------- Аргументы CLI ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="omnimind-quickstart", description="OmniMind Core Quickstart CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # prompt-preview
    sp = sub.add_parser("prompt-preview", help="Render prompt (ChatML) and preview text")
    sp.add_argument("--id", required=True, help="prompt id (e.g., summarize, plan, extract)")
    sp.add_argument("--version", default=None, help="prompt version (e.g., 1.0)")
    sp.add_argument("--locale", default="ru", help="locale (ru|en)")
    sp.add_argument("--text", default=None, help="text for summarize/extract")
    sp.add_argument("--style", default=None, help="style hint")
    sp.add_argument("--max-words", type=int, default=None, dest="max_words", help="length limit in words")
    sp.add_argument("--var", action="append", help="additional variables key=value", default=[])
    sp.set_defaults(func=cmd_prompt_preview)

    # embed
    sp = sub.add_parser("embed", help="Compute embeddings for given texts")
    sp.add_argument("texts", nargs="+", help="texts to embed")
    sp.set_defaults(func=cmd_embed)

    # plan-direct
    sp = sub.add_parser("plan-direct", help="Plan synchronously via LLM (no queue)")
    sp.add_argument("--goal", required=True, help="goal to plan")
    sp.add_argument("--constraints", default=None, help="constraints")
    sp.add_argument("--context", default=None, help="context")
    sp.add_argument("--locale", default="ru", help="ru|en")
    sp.set_defaults(func=cmd_plan_direct)

    # queue-publish-plan
    sp = sub.add_parser("queue-publish-plan", help="Publish a plan.request to Redis Streams")
    sp.add_argument("--goal", required=True, help="goal")
    sp.add_argument("--constraints", default=None, help="constraints")
    sp.add_argument("--context", default=None, help="context")
    sp.add_argument("--locale", default="ru", help="ru|en")
    sp.add_argument("--request-id", default=None, help="idempotency key / request_id")
    sp.set_defaults(func=cmd_queue_publish_plan)

    # worker-planner
    sp = sub.add_parser("worker-planner", help="Run planner worker (until Ctrl+C)")
    sp.set_defaults(func=cmd_worker_planner)

    # http-memory-append
    sp = sub.add_parser("http-memory-append", help="POST /v1/memory/append to test Memory API")
    sp.add_argument("--url", required=True, help="base URL (e.g., http://localhost:8080)")
    sp.add_argument("--agent-id", required=True)
    sp.add_argument("--type", required=True, choices=["EPISODIC", "SEMANTIC", "LONG_TERM", "VECTOR"])
    sp.add_argument("--json", required=True, help="payload JSON string, e.g. '{\"note\":\"hi\"}'")
    sp.add_argument("--relevance", type=float, default=0.5)
    sp.set_defaults(func=cmd_http_memory_append)

    # http-memory-query
    sp = sub.add_parser("http-memory-query", help="POST /v1/memory/query to test Memory API")
    sp.add_argument("--url", required=True, help="base URL (e.g., http://localhost:8080)")
    sp.add_argument("--agent-id", default=None)
    sp.add_argument("--text", default=None)
    sp.add_argument("--types", nargs="*", default=None, help="filter by types")
    sp.add_argument("--page-size", type=int, default=10)
    sp.set_defaults(func=cmd_http_memory_query)

    return p


# ---------- Точка входа ----------

def main() -> None:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(args.func(args))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
