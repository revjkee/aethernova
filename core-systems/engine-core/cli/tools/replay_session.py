#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Industrial-grade session replayer for JSONL event logs.

FEATURES
- Input: JSONL (optionally gz/xz). First line may be meta: {"_meta": {...}}
- Event schema (flexible): {"ts": float|str, "type": str, "payload": any, "checksum": "sha256:..."} (+ extra fields ok)
- Time control: real pacing by delta ts; --speed <x>; --no-sleep; --from/--to wallclock or monotonic offsets
- Filtering: --filter 'expr' (safe eval with limited builtins), --select 'a,b,c' to project fields
- Integrity: verify checksum (sha256) over normalized payload bytes; --require-checksum to drop events without it
- Resume: --offset <lines> to skip N lines (fast forward)
- Sinks: stdout (pretty/compact), file (append), HTTP POST (aiohttp), WebSocket (client)
- Metrics: printed on exit and optionally emitted as JSON
- Robustness: malformed lines are counted and skipped (unless --strict), backpressure on sinks, graceful shutdown (SIGINT/SIGTERM)

USAGE
  python -m engine.tools.replay_session --input session.jsonl.gz --speed 4 --filter "event['type']=='tick'" --sink stdout
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import gzip
import io
import json
import logging
import lzma
import math
import os
import signal
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Dict, Optional, Protocol, Tuple, List, Iterable, Union, Callable

try:
    from pydantic import BaseModel, Field, ValidationError
except Exception as e:  # pragma: no cover
    raise RuntimeError("replay_session requires 'pydantic'") from e

LOG = logging.getLogger("engine.tools.replay")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter(fmt='[%(asctime)s] %(levelname)s %(name)s: %(message)s'))
    LOG.addHandler(h)
LOG.setLevel(os.environ.get("REPLAY_LOG_LEVEL", "INFO").upper())


# =========================
# Models
# =========================
class Event(BaseModel):
    ts: Union[float, str] = Field(..., description="Event timestamp (seconds since epoch or ISO 8601).")
    type: str = Field(..., description="Event type string.")
    payload: Any = Field(default=None, description="Arbitrary JSON payload.")
    checksum: Optional[str] = Field(default=None, description="sha256:<hex> over canonical payload bytes.")

    # Extra fields allowed for flexibility
    class Config:
        extra = "allow"

class Meta(BaseModel):
    session_id: Optional[str] = None
    clock: Optional[str] = Field(default="epoch", description="epoch|monotonic|logical")
    created_at: Optional[Union[float, str]] = None
    description: Optional[str] = None


@dataclass
class Metrics:
    total_lines: int = 0
    meta_lines: int = 0
    events_ok: int = 0
    events_failed: int = 0
    events_filtered: int = 0
    checksum_failed: int = 0
    emitted: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    first_event_ts: Optional[float] = None
    last_event_ts: Optional[float] = None

    def snapshot(self) -> Dict[str, Any]:
        d = asdict(self)
        d["wall_ms"] = int((self.end_time - self.start_time) * 1000) if self.end_time and self.start_time else None
        return d


# =========================
# Utility
# =========================
def _parse_ts(v: Union[float, str]) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    # ISO 8601 fallback without external deps (lenient)
    # Accept "YYYY-MM-DDTHH:MM:SS[.sss]Z" or with timezone "+HH:MM"
    s = str(v).strip()
    try:
        from datetime import datetime, timezone
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
        return dt.timestamp()
    except Exception:
        # last resort: float string
        try:
            return float(s)
        except Exception as e:
            raise ValueError(f"Invalid timestamp: {v}") from e


def _canon_bytes(payload: Any) -> bytes:
    # Canonical JSON for hashing
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _verify_checksum(evt: Event) -> bool:
    if not evt.checksum:
        return False
    try:
        algo, hex_ = evt.checksum.split(":", 1)
        if algo.lower() != "sha256" or len(hex_) != 64:
            return False
        import hashlib
        h = hashlib.sha256(_canon_bytes(evt.payload)).hexdigest()
        return h.lower() == hex_.lower()
    except Exception:
        return False


def _open_any(path: Path) -> io.TextIOBase:
    """Open normal/gz/xz file as text (utf-8)."""
    suf = path.suffix.lower()
    if suf == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8")
    if suf == ".xz":
        return io.TextIOWrapper(lzma.open(path, "rb"), encoding="utf-8")
    # Support .jsonl or plain
    return open(path, "r", encoding="utf-8")


def _safe_eval_factory(expr: str) -> Callable[[Dict[str, Any]], bool]:
    # Very restricted eval for --filter expressions
    allowed_names = {
        "len": len, "abs": abs, "min": min, "max": max, "round": round, "math": math,
    }
    code = compile(expr, "<filter>", "eval")
    def _fn(event: Dict[str, Any]) -> bool:
        return bool(eval(code, {"__builtins__": {}}, {"event": event, **allowed_names}))
    return _fn


# =========================
# Sinks
# =========================
class Sink(Protocol):
    async def emit(self, event: Dict[str, Any]) -> None: ...
    async def close(self) -> None: ...


class StdoutSink:
    def __init__(self, pretty: bool = False) -> None:
        self.pretty = pretty

    async def emit(self, event: Dict[str, Any]) -> None:
        if self.pretty:
            print(json.dumps(event, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(event, ensure_ascii=False, separators=(",", ":")))

    async def close(self) -> None:
        await asyncio.sleep(0)


class FileSink:
    def __init__(self, path: Path, append: bool = True) -> None:
        self._f = open(path, "a" if append else "w", encoding="utf-8")

    async def emit(self, event: Dict[str, Any]) -> None:
        self._f.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        self._f.flush()

    async def close(self) -> None:
        self._f.close()


class HttpSink:
    def __init__(self, url: str, timeout: float = 10.0, batch: int = 1) -> None:
        try:
            import aiohttp
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("HttpSink requires 'aiohttp'") from e
        self.url = url
        self.timeout = timeout
        self.batch = max(1, int(batch))
        self._buf: List[Dict[str, Any]] = []
        self._session: Optional["aiohttp.ClientSession"] = None

    async def _ensure(self) -> "aiohttp.ClientSession":
        import aiohttp
        if not self._session:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
        return self._session

    async def emit(self, event: Dict[str, Any]) -> None:
        self._buf.append(event)
        if len(self._buf) >= self.batch:
            await self._flush()

    async def _flush(self) -> None:
        if not self._buf:
            return
        sess = await self._ensure()
        payload = json.dumps(self._buf, ensure_ascii=False).encode("utf-8")
        self._buf.clear()
        async with sess.post(self.url, data=payload, headers={"content-type": "application/json"}) as resp:
            if resp.status >= 400:
                text = await resp.text()
                raise RuntimeError(f"HTTP sink {resp.status}: {text}")

    async def close(self) -> None:
        await self._flush()
        if self._session:
            await self._session.close()
            self._session = None


class WsSink:
    def __init__(self, url: str, ping_interval: float = 5.0) -> None:
        try:
            import websockets  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("WsSink requires 'websockets'") from e
        self.url = url
        self.ping_interval = ping_interval
        self._ws = None

    async def _ensure(self):
        import websockets  # type: ignore
        if self._ws is None:
            self._ws = await websockets.connect(self.url, ping_interval=self.ping_interval)
        return self._ws

    async def emit(self, event: Dict[str, Any]) -> None:
        ws = await self._ensure()
        await ws.send(json.dumps(event, ensure_ascii=False))

    async def close(self) -> None:
        if self._ws:
            await self._ws.close()
            self._ws = None


# =========================
# Reader
# =========================
async def read_lines(path: Path, *, offset: int = 0) -> AsyncIterator[Tuple[int, str]]:
    """Async line reader with optional initial skip."""
    loop = asyncio.get_running_loop()
    def _iter():
        with _open_any(path) as f:
            for i, line in enumerate(f, start=1):
                if i <= offset:
                    continue
                yield (i, line.rstrip("\n"))
    for item in await loop.run_in_executor(None, lambda: list(_iter())):
        yield item


# =========================
# Replay core
# =========================
@dataclass
class ReplayConfig:
    input: Path
    sink: Sink
    speed: float = 1.0
    no_sleep: bool = False
    from_ts: Optional[float] = None
    to_ts: Optional[float] = None
    offset: int = 0
    filter_expr: Optional[str] = None
    selector: Optional[List[str]] = None
    require_checksum: bool = False
    strict: bool = False
    metrics_json: Optional[Path] = None


async def replay(cfg: ReplayConfig) -> Metrics:
    metrics = Metrics(start_time=time.perf_counter())
    stopper = asyncio.Event()

    def _handle_signal():
        LOG.warning("interrupt received, stopping…")
        stopper.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(Exception):
            asyncio.get_running_loop().add_signal_handler(sig, _handle_signal)

    filt = _safe_eval_factory(cfg.filter_expr) if cfg.filter_expr else None
    selector = cfg.selector

    base_ts: Optional[float] = None
    last_ts: Optional[float] = None

    async for lineno, raw in read_lines(cfg.input, offset=cfg.offset):
        if stopper.is_set():
            break
        metrics.total_lines += 1
        if not raw.strip():
            continue
        # meta line?
        if raw.lstrip().startswith('{"_meta"'):
            metrics.meta_lines += 1
            # meta is optional, parse leniently
            with contextlib.suppress(Exception):
                obj = json.loads(raw)
                Meta.parse_obj(obj.get("_meta", {}))
            continue
        # parse event
        try:
            obj = json.loads(raw)
            evt = Event.parse_obj(obj)
        except (json.JSONDecodeError, ValidationError) as e:
            metrics.events_failed += 1
            msg = f"line {lineno}: parse error: {e}"
            if cfg.strict:
                raise RuntimeError(msg)
            LOG.debug(msg)
            continue

        # timestamp
        try:
            ts = _parse_ts(evt.ts)
        except Exception as e:
            metrics.events_failed += 1
            if cfg.strict:
                raise
            LOG.debug("line %d: bad ts: %s", lineno, e)
            continue

        # window filter
        if cfg.from_ts and ts < cfg.from_ts:
            metrics.events_filtered += 1
            continue
        if cfg.to_ts and ts > cfg.to_ts:
            metrics.events_filtered += 1
            continue

        # checksum
        if evt.checksum:
            ok = _verify_checksum(evt)
            if not ok:
                metrics.checksum_failed += 1
                if cfg.strict:
                    raise RuntimeError(f"line {lineno}: checksum mismatch")
                LOG.debug("line %d: checksum mismatch", lineno)
                continue
        elif cfg.require_checksum:
            metrics.events_filtered += 1
            continue

        # user filter
        if filt:
            try:
                if not filt(obj):
                    metrics.events_filtered += 1
                    continue
            except Exception as e:
                metrics.events_failed += 1
                if cfg.strict:
                    raise
                LOG.debug("line %d: filter error: %s", lineno, e)
                continue

        # pacing
        if not cfg.no_sleep:
            if base_ts is None:
                base_ts = ts
                last_ts = ts
            else:
                assert last_ts is not None
                delta = max(0.0, ts - last_ts)
                last_ts = ts
                delay = delta / max(1e-9, cfg.speed)
                # avoid long sleeps in case of large gaps
                if delay > 0:
                    try:
                        await asyncio.wait_for(asyncio.sleep(delay), timeout=delay + 1.0)
                    except asyncio.TimeoutError:
                        pass

        # projection
        out_event: Dict[str, Any]
        if selector:
            out_event = {k: obj.get(k) for k in selector}
        else:
            out_event = obj

        # emit
        try:
            await cfg.sink.emit(out_event)
            metrics.emitted += 1
            metrics.events_ok += 1
        except Exception as e:
            metrics.events_failed += 1
            if cfg.strict:
                raise
            LOG.warning("line %d: sink error: %s", lineno, e)

        # store first/last
        metrics.first_event_ts = metrics.first_event_ts or ts
        metrics.last_event_ts = ts

    metrics.end_time = time.perf_counter()
    return metrics


# =========================
# CLI
# =========================
def _build_sink(args: argparse.Namespace) -> Sink:
    if args.sink == "stdout":
        return StdoutSink(pretty=args.pretty)
    if args.sink == "file":
        if not args.output:
            raise SystemExit("--output is required for sink=file")
        return FileSink(Path(args.output), append=not args.truncate)
    if args.sink == "http":
        return HttpSink(args.url, timeout=args.http_timeout, batch=args.batch)
    if args.sink == "ws":
        return WsSink(args.url, ping_interval=args.ws_ping)
    raise SystemExit(f"Unknown sink: {args.sink}")

def _parse_time_boundary(v: Optional[str]) -> Optional[float]:
    if not v:
        return None
    try:
        return _parse_ts(v)
    except Exception as e:
        raise SystemExit(f"Bad time value '{v}': {e}")

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="replay_session", description="Replay JSONL event sessions with precise timing.")
    p.add_argument("--input", "-i", required=True, help="Path to JSONL(.gz|.xz) session file")
    p.add_argument("--offset", type=int, default=0, help="Skip first N lines (resume)")
    p.add_argument("--speed", type=float, default=1.0, help="Speed multiplier (e.g., 2.0 = 2x faster)")
    p.add_argument("--no-sleep", action="store_true", help="Do not sleep between events (as fast as possible)")
    p.add_argument("--from", dest="from_ts", default=None, help="Lower bound ts (epoch float or ISO)")
    p.add_argument("--to", dest="to_ts", default=None, help="Upper bound ts (epoch float or ISO)")
    p.add_argument("--filter", dest="filter_expr", default=None, help="Python expr over 'event', e.g. \"event['type']=='tick'\"")
    p.add_argument("--select", dest="selector", default=None, help="Comma-separated list of fields to emit")
    p.add_argument("--require-checksum", action="store_true", help="Drop events without checksum")
    p.add_argument("--strict", action="store_true", help="Strict mode: fail on parse/checksum/sink errors")
    p.add_argument("--metrics-json", default=None, help="Write metrics JSON to file")

    sinks = p.add_argument_group("sinks")
    sinks.add_argument("--sink", choices=["stdout", "file", "http", "ws"], default="stdout")
    sinks.add_argument("--pretty", action="store_true", help="Pretty print for stdout sink")
    sinks.add_argument("--output", help="Output file for sink=file")
    sinks.add_argument("--truncate", action="store_true", help="Truncate output file before writing")
    sinks.add_argument("--url", help="URL for sink=http/ws")
    sinks.add_argument("--http-timeout", type=float, default=10.0)
    sinks.add_argument("--batch", type=int, default=1, help="HTTP sink batch size")
    sinks.add_argument("--ws-ping", type=float, default=5.0)

    args = p.parse_args(argv)

    # Validate boundaries
    from_ts = _parse_time_boundary(args.from_ts)
    to_ts = _parse_time_boundary(args.to_ts)
    if from_ts and to_ts and from_ts > to_ts:
        raise SystemExit("--from must be <= --to")

    selector = [s.strip() for s in args.selector.split(",")] if args.selector else None

    sink = _build_sink(args)

    cfg = ReplayConfig(
        input=Path(args.input),
        sink=sink,
        speed=max(1e-6, float(args.speed)),
        no_sleep=bool(args.no_sleep),
        from_ts=from_ts,
        to_ts=to_ts,
        offset=max(0, int(args.offset)),
        filter_expr=args.filter_expr,
        selector=selector,
        require_checksum=bool(args.require_checksum),
        strict=bool(args.strict),
        metrics_json=Path(args.metrics_json) if args.metrics_json else None,
    )

    async def _run():
        try:
            metrics = await replay(cfg)
            if cfg.metrics_json:
                Path(cfg.metrics_json).write_text(json.dumps(metrics.snapshot(), ensure_ascii=False, indent=2), encoding="utf-8")
            # Always print concise metrics summary to stderr
            m = metrics.snapshot()
            LOG.info("done: events_ok=%d emitted=%d filtered=%d failed=%d checksum_failed=%d wall_ms=%s",
                     m["events_ok"], m["emitted"], m["events_filtered"], m["events_failed"], m["checksum_failed"], m["wall_ms"])
        finally:
            with contextlib.suppress(Exception):
                await sink.close()

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
