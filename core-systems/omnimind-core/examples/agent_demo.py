from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Tuple

# ---------------- Optional deps ----------------
try:
    import httpx  # optional for HttpGet tool
    _HAVE_HTTPX = True
except Exception:
    _HAVE_HTTPX = False

try:
    from ops.omnimind.settings import get_settings
except Exception:
    def get_settings():
        # Fallback minimal settings
        class _S:  # noqa: N801
            app_name = "omnimind-core"
            version = "0.0.0"
            environment = "dev"
            telemetry = type("T", (), {"prometheus_enabled": False, "prometheus_path": "/metrics"})()
            tracing = type("Tr", (), {"enabled": False})()
            database = type("Db", (), {"dsn": None})()
        return _S()

try:
    # Your industrial retriever from omnimind/omnimind/memory/retriever.py
    from omnimind.memory.retriever import (
        Retriever, QueryParams, QueryFilter,
        build_pgvector_retriever, build_inmemory_retriever, Document,
    )
except Exception as e:
    raise RuntimeError("Unable to import omnimind.memory.retriever; ensure module is available") from e


# ---------------- Logging ----------------
def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter(fmt="%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(h)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


log = logging.getLogger("examples.agent_demo")


# ---------------- Chat model protocol ----------------
class ChatModel(Protocol):
    async def acomplete(self, messages: List[Dict[str, str]], tools_schema: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Return dict with keys:
          - role: "assistant"
          - content: str (may be empty if tool_calls provided)
          - tool_calls: Optional[List[{"id": str, "type":"function", "function":{"name": str, "arguments": dict}}]]
        """
        ...


class SimpleTemplateModel:
    """
    Lightweight demo model:
      - If tool schema present and prompt matches calc/http/memory intents, emits tool_calls.
      - Else returns a templated answer with retrieved context (RAG-lite).
    Replace with a real LLM in production.
    """
    def __init__(self, retriever: Retriever):
        self.retriever = retriever

    async def acomplete(self, messages: List[Dict[str, str]], tools_schema: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        tool_calls: List[Dict[str, Any]] = []

        wants_calc = any(tok in user for tok in ["calculate", "calc", "посчитай", "сколько будет", "="])
        wants_http = any(tok in user.lower() for tok in ["http://", "https://"])
        wants_memory = any(tok in user.lower() for tok in ["найди", "поиск", "memory", "pgvector", "retriever", "документ", "context"])

        # simple planner
        if tools_schema:
            if wants_calc and _tool_exists("calculator", tools_schema):
                tool_calls.append(_tool_call("calculator", {"expression": user}))
            if wants_http and _tool_exists("http_get", tools_schema):
                url = _extract_url(user)
                if url:
                    tool_calls.append(_tool_call("http_get", {"url": url, "timeout_s": 5.0}))
            if wants_memory and _tool_exists("memory_search", tools_schema):
                # Query top-5
                tool_calls.append(_tool_call("memory_search", {"query": user, "top_k": 5, "namespace": "docs"}))

        # If tools planned, return empty content for now
        if tool_calls:
            return {"role": "assistant", "content": "", "tool_calls": tool_calls}

        # Otherwise produce templated answer with RAG-lite
        ctx = await self._rag_context(user)
        content = "Ответ:\n" + self._format_answer(user, ctx)
        return {"role": "assistant", "content": content}

    async def _rag_context(self, query: str) -> List[str]:
        try:
            res = await self.retriever.query(QueryParams(query=query, top_k=3, namespace="docs"))
            return [s.doc.text for s in res]
        except Exception:
            return []

    def _format_answer(self, user: str, ctx: List[str]) -> str:
        out = []
        out.append(f"Запрос: {user}")
        if ctx:
            out.append("Контекст:")
            for i, c in enumerate(ctx, 1):
                out.append(f"[{i}] {c[:500]}")
        else:
            out.append("Контекст не найден. Отвечаю на основе общих сведений.")
        out.append("Итог: с учётом вышеизложенного это предварительный ответ. Для точности используйте инструменты или добавьте источники.")
        return "\n".join(out)


def _tool_exists(name: str, tools_schema: List[Dict[str, Any]]) -> bool:
    return any(t.get("function", {}).get("name") == name for t in tools_schema)


def _tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": f"tc_{int(time.time()*1000)}", "type": "function", "function": {"name": name, "arguments": arguments}}


def _extract_url(text: str) -> Optional[str]:
    for tok in text.split():
        if tok.startswith("http://") or tok.startswith("https://"):
            return tok.strip()
    return None


# ---------------- Tools and execution ----------------
class Tool(Protocol):
    name: str
    description: str
    parameters: Dict[str, Any]
    async def run(self, **kwargs) -> Dict[str, Any]: ...


@dataclass
class CalculatorTool:
    name: str = "calculator"
    description: str = "Безопасная арифметика: + - * / // % **, скобки. Примеры: '2+2', '(3+4)*5'."
    parameters: Dict[str, Any] = None  # filled in __post_init__

    def __post_init__(self):
        self.parameters = {
            "type": "object",
            "properties": {"expression": {"type": "string", "description": "Арифметическое выражение"}},
            "required": ["expression"],
        }

    async def run(self, **kwargs) -> Dict[str, Any]:
        expr = str(kwargs.get("expression", ""))
        value = _safe_eval(expr)
        return {"ok": True, "result": value}


@dataclass
class TimeTool:
    name: str = "time_now"
    description: str = "Текущее время в ISO 8601 UTC."
    parameters: Dict[str, Any] = None

    def __post_init__(self):
        self.parameters = {"type": "object", "properties": {}, "additionalProperties": False}

    async def run(self, **kwargs) -> Dict[str, Any]:
        import datetime as dt
        return {"ok": True, "iso_utc": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"}


@dataclass
class HttpGetTool:
    name: str = "http_get"
    description: str = "HTTP GET с тайм-аутом (5–10с). Возвращает заголовки и первые 2 КБ."
    parameters: Dict[str, Any] = None

    def __post_init__(self):
        self.parameters = {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "timeout_s": {"type": "number", "minimum": 1, "maximum": 30, "default": 5},
            },
            "required": ["url"],
            "additionalProperties": False,
        }

    async def run(self, **kwargs) -> Dict[str, Any]:
        if not _HAVE_HTTPX:
            return {"ok": False, "error": "httpx not installed"}
        url = str(kwargs["url"])
        timeout = float(kwargs.get("timeout_s", 5.0))
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            r = await client.get(url)
            snippet = r.text[:2048]
            headers = {k: v for k, v in r.headers.items()}
            return {"ok": True, "status": r.status_code, "headers": headers, "body_snippet": snippet}


@dataclass
class MemorySearchTool:
    retriever: Retriever
    name: str = "memory_search"
    description: str = "Поиск в памяти (pgvector/in-memory). Возвращает top_k результатов с оценкой."
    parameters: Dict[str, Any] = None

    def __post_init__(self):
        self.parameters = {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "top_k": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
                "namespace": {"type": "string", "default": "default"},
            },
            "required": ["query"],
            "additionalProperties": False,
        }

    async def run(self, **kwargs) -> Dict[str, Any]:
        query = str(kwargs["query"])
        top_k = int(kwargs.get("top_k", 5))
        ns = str(kwargs.get("namespace", "default"))
        res = await self.retriever.query(QueryParams(query=query, top_k=top_k, namespace=ns))
        items = [{"doc_id": s.doc.doc_id, "text": s.doc.text, "score": s.score, "source": s.doc.source, "namespace": s.doc.namespace} for s in res]
        return {"ok": True, "items": items}


def build_tools(retriever: Retriever) -> List[Tool]:
    return [CalculatorTool(), TimeTool(), HttpGetTool(), MemorySearchTool(retriever=retriever)]


def tool_schemas(tools: Iterable[Tool]) -> List[Dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            },
        }
        for t in tools
    ]


async def execute_tool(tools: List[Tool], name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    tool = next((t for t in tools if t.name == name), None)
    if not tool:
        return {"ok": False, "error": f"tool '{name}' not found"}
    try:
        return await tool.run(**args)
    except Exception as e:
        return {"ok": False, "error": repr(e)}


# ---------------- Safe calculator ----------------
import ast
import operator as op

_ALLOWED_BIN = {
    ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul, ast.Div: op.truediv,
    ast.FloorDiv: op.floordiv, ast.Mod: op.mod, ast.Pow: op.pow,
}
_ALLOWED_UN = {ast.UAdd: op.pos, ast.USub: op.neg}

def _safe_eval(expr: str) -> float:
    """
    Evaluate arithmetic expression safely.
    Limits power exponent and recursion depth.
    """
    node = ast.parse(expr, mode="eval")
    return _eval_node(node.body, depth=0)

def _eval_node(node: ast.AST, depth: int) -> float:
    if depth > 32:
        raise ValueError("expression too deep")
    if isinstance(node, ast.Num):  # type: ignore[deprecated]
        return node.n  # type: ignore
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_BIN:
        left = _eval_node(node.left, depth + 1)
        right = _eval_node(node.right, depth + 1)
        if isinstance(node.op, ast.Pow) and abs(right) > 10:
            raise ValueError("exponent too large")
        return _ALLOWED_BIN[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_UN:
        val = _eval_node(node.operand, depth + 1)
        return _ALLOWED_UN[type(node.op)](val)
    if isinstance(node, ast.Expr):
        return _eval_node(node.value, depth + 1)
    if isinstance(node, ast.Call) or isinstance(node, ast.Attribute) or isinstance(node, ast.Subscript) or isinstance(node, ast.Name):
        raise ValueError("functions/variables not allowed")
    raise ValueError("unsupported expression")


# ---------------- Agent ----------------
@dataclass
class Agent:
    model: ChatModel
    tools: List[Tool]
    retriever: Retriever
    timeout_s: float = 20.0
    max_tool_hops: int = 3

    async def run(self, prompt: str) -> str:
        """
        One-turn agent with up to N tool hops and RAG context fused in the final answer.
        """
        messages: List[Dict[str, str]] = [
            {"role": "system", "content": "Ты профессиональный ассистент. Используй инструменты, если это улучшит точность."},
            {"role": "user", "content": prompt},
        ]
        schemas = tool_schemas(self.tools)

        for hop in range(self.max_tool_hops + 1):
            with _timeout(self.timeout_s):
                resp = await self.model.acomplete(messages, tools_schema=schemas)
            tool_calls = resp.get("tool_calls") or []
            content = (resp.get("content") or "").strip()

            if tool_calls:
                # Execute tools sequentially and append tool results to messages
                for tc in tool_calls:
                    name = tc["function"]["name"]
                    args = tc["function"]["arguments"]
                    log.debug("Executing tool: %s(%s)", name, args)
                    with _timeout(self.timeout_s):
                        result = await execute_tool(self.tools, name, args)
                    messages.append({"role": "tool", "content": json.dumps({"tool": name, "result": result}, ensure_ascii=False)})
                # Ask model again with tool outputs
                continue

            # No tool call -> final
            if not content:
                content = "Не удалось получить ответ."
            return content

        return "Достигнут лимит шагов; промежуточные результаты в логах."

# ---------------- Timeout ctx ----------------
@contextlib.asynccontextmanager
async def _timeout(seconds: float):
    try:
        yield
    except asyncio.TimeoutError:
        raise
    except Exception:
        raise


# ---------------- Bootstrap ----------------
async def _build_retriever(settings) -> Retriever:
    dsn = getattr(getattr(settings, "database", None), "dsn", None)
    dim = int(os.getenv("OMNIMIND_EMBED_DIM", "384"))
    table = os.getenv("OMNIMIND_PGVECTOR_TABLE", "memory_items")
    use_ivfflat = os.getenv("OMNIMIND_PGVECTOR_IVFFLAT", "false").lower() == "true"
    cache_path = os.getenv("OMNIMIND_EMBED_CACHE", "/tmp/omni_embed_cache.sqlite")

    embed_factory_path = os.getenv("OMNIMIND_EMBED_FACTORY", "")
    embed_factory = None
    if embed_factory_path:
        mod_name, func_name = embed_factory_path.rsplit(":", 1)
        mod = __import__(mod_name, fromlist=[func_name])
        embed_factory = getattr(mod, func_name)

    if dsn:
        return await build_pgvector_retriever(
            pg_dsn=dsn, dim=dim, table=table, use_ivfflat=use_ivfflat, cache_path=cache_path, embed_model_factory=embed_factory
        )
    return await build_inmemory_retriever(dim=dim, cache_path=cache_path)


async def _seed_demo_docs(r: Retriever) -> None:
    """
    Seed demo documents if namespace 'docs' seems empty.
    """
    texts = [
        "OmniMind Core использует pgvector для семантического поиска и поддерживает MMR переранжирование.",
        "Retriever поддерживает InMemory и PostgreSQL/pgvector хранилища. Настройки берутся из ops/omnimind/settings.py.",
        "Worker memory_indexer читает задания из Redis Streams или Kafka и индексирует чанки текста.",
        "Observability Adapter включает метрики Prometheus и трассировку OpenTelemetry.",
    ]
    for t in texts:
        await r.upsert_text(text=t, namespace="docs", source="demo", chunk=False)


async def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="OmniMind Agent Demo (industrial-grade example)")
    parser.add_argument("prompt", nargs="*", help="Запрос (если пусто — включится REPL)")
    parser.add_argument("--log", default=os.getenv("LOG_LEVEL", "INFO"))
    parser.add_argument("--repl", action="store_true", help="Интерактивный режим")
    parser.add_argument("--timeout", type=float, default=float(os.getenv("AGENT_TIMEOUT", "20.0")))
    parser.add_argument("--max-hops", type=int, default=int(os.getenv("AGENT_MAX_HOPS", "3")))
    args = parser.parse_args(argv)

    setup_logging(args.log)
    settings = get_settings()
    retriever = await _build_retriever(settings)
    await _seed_demo_docs(retriever)

    tools = build_tools(retriever)
    model = SimpleTemplateModel(retriever=retriever)
    agent = Agent(model=model, tools=tools, retriever=retriever, timeout_s=args.timeout, max_tool_hops=args.max_hops)

    # graceful shutdown
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    async def _run_prompt(p: str):
        try:
            ans = await agent.run(p)
            print(ans)
        except Exception as e:
            log.error("Agent error: %s", e, exc_info=True)

    if args.repl or not args.prompt:
        print("REPL: введите запрос (Ctrl+C для выхода)")
        while not stop.is_set():
            try:
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                await _run_prompt(line)
            except KeyboardInterrupt:
                break
    else:
        await _run_prompt(" ".join(args.prompt))

    with contextlib.suppress(Exception):
        await retriever.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
