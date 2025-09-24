# physical-integration-core/cli/main.py
# Python 3.10+
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# ---------- Optional uvloop ----------
try:  # pragma: no cover
    import uvloop  # type: ignore
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())  # noqa
except Exception:
    pass

# ---------- Local modules (provided elsewhere in this repo) ----------
# Logging (structured)
try:
    from physical_integration.observability.logging import (
        LoggingConfig,
        configure_logging,
        get_logger,
        set_context,
    )
except Exception as _e:  # pragma: no cover
    # Minimal fallback if observability module is not available
    import logging

    class _Dummy:
        def __init__(self) -> None:
            self._log = logging.getLogger("pic-cli")
            logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        def __call__(self, *_, **__):  # type: ignore
            return self._log
    def configure_logging(_: Any) -> Any:  # type: ignore
        return _Dummy()()
    def get_logger(name: Optional[str] = None):  # type: ignore
        import logging
        return logging.getLogger(name or "pic-cli")
    def set_context(**_: Any) -> None:  # type: ignore
        return
    @dataclass
    class LoggingConfig:
        service: str = "physical-integration-core"
        env: str = os.getenv("ENV", "dev")
        level: str = os.getenv("LOG_LEVEL", "INFO")
        json_output: bool = True

# Telemetry aggregators
try:
    from physical_integration.telemetry.aggregators import (
        SeriesPoint,
        AggregationSpec,
        aggregate_timeseries,
        fill_missing_buckets,
    )
except Exception:  # pragma: no cover
    SeriesPoint = AggregationSpec = aggregate_timeseries = fill_missing_buckets = None  # type: ignore

# Video FFmpeg bridge
try:
    from physical_integration.video.ffmpeg_bridge import (
        FFmpegBridge,
        BridgeConfig,
        TranscodeConfig,
        HLSConfig,
        ThumbnailConfig,
    )
except Exception:  # pragma: no cover
    FFmpegBridge = BridgeConfig = TranscodeConfig = HLSConfig = ThumbnailConfig = None  # type: ignore

# Registry repository (PostgreSQL)
try:
    from physical_integration.registry.repository import (
        RegistryConfig,
        PgRegistryRepository,
        RepositoryError,
        NotFoundError,
        ConflictError,
    )
except Exception:  # pragma: no cover
    RegistryConfig = PgRegistryRepository = RepositoryError = NotFoundError = ConflictError = None  # type: ignore

# Twin synchronizer
try:
    from physical_integration.twin.synchronizer import (
        SynchronizerConfig,
        TwinSynchronizer,
        InMemoryTwinStore,
    )
except Exception:  # pragma: no cover
    SynchronizerConfig = TwinSynchronizer = InMemoryTwinStore = None  # type: ignore

LOG = get_logger("pic.cli")


# =============================================================================
# Utilities
# =============================================================================

def _eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, file=sys.stderr, **kwargs)

def _json_dump(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str))

def _ensure_tz(dt: str) -> datetime:
    # RFC3339-ish
    s = dt.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    d = datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d

def _read_json_or_ndjson(path: Optional[str]) -> List[Dict[str, Any]]:
    data: List[Dict[str, Any]] = []
    if path and path != "-":
        content = Path(path).read_text(encoding="utf-8")
        try:
            js = json.loads(content)
            if isinstance(js, list):
                for row in js:
                    if isinstance(row, dict):
                        data.append(row)
            elif isinstance(js, dict):
                data.append(js)
            else:
                raise ValueError("Unsupported JSON structure")
        except json.JSONDecodeError:
            # try NDJSON
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                data.append(json.loads(line))
    else:
        buf = sys.stdin.read()
        try:
            js = json.loads(buf)
            if isinstance(js, list):
                data.extend([row for row in js if isinstance(row, dict)])
            elif isinstance(js, dict):
                data.append(js)
            else:
                raise ValueError("Unsupported JSON structure")
        except json.JSONDecodeError:
            for line in buf.splitlines():
                line = line.strip()
                if not line:
                    continue
                data.append(json.loads(line))
    return data

def _maybe_env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.getenv(name, default)

def _load_config_file(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    text = p.read_text(encoding="utf-8")
    # Try YAML, then JSON, then simple KEY=VALUE lines
    try:
        import yaml  # type: ignore
        return dict(yaml.safe_load(text) or {})
    except Exception:
        pass
    try:
        return dict(json.loads(text))
    except Exception:
        pass
    cfg: Dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        cfg[k.strip()] = v.strip()
    return cfg

def _import_from_string(spec: str) -> Any:
    """
    Import "package.module:attribute" or "package.module.Class".
    """
    if ":" in spec:
        mod, attr = spec.split(":", 1)
    else:
        parts = spec.split(".")
        mod, attr = ".".join(parts[:-1]), parts[-1]
    m = importlib.import_module(mod)
    return getattr(m, attr)

async def _graceful(coro: Awaitable[Any], *, timeout: float = 5.0) -> Any:
    """
    Run coroutine with graceful shutdown on SIGINT/SIGTERM.
    """
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    def _handler(*_: Any) -> None:
        stop.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _handler)
        loop.add_signal_handler(signal.SIGTERM, _handler)
    except NotImplementedError:  # Windows
        signal.signal(signal.SIGINT, lambda *_: stop.set())  # type: ignore
        signal.signal(signal.SIGTERM, lambda *_: stop.set())  # type: ignore

    task = asyncio.create_task(coro)
    done, pending = await asyncio.wait({task, asyncio.create_task(stop.wait())}, return_when=asyncio.FIRST_COMPLETED)
    if task in done:
        return task.result()
    # Stop requested
    try:
        task.cancel()
        await asyncio.wait_for(task, timeout=timeout)
    except Exception:
        pass
    return None


# =============================================================================
# Command implementations
# =============================================================================

# --- registry ---

async def cmd_registry_health(args: argparse.Namespace) -> int:
    if not PgRegistryRepository or not RegistryConfig:
        _eprint("Registry module is unavailable")
        return 2
    cfg = RegistryConfig(
        dsn=args.dsn or _maybe_env("PIC_DB_DSN"),
        pool_size=args.pool_size,
        max_overflow=0,
        echo=args.sql_echo,
    )
    if not cfg.dsn:
        _eprint("Missing DSN: pass --dsn or set PIC_DB_DSN")
        return 2
    repo = PgRegistryRepository(cfg)
    try:
        res = await repo.health()
        _json_dump({"ok": bool(res.get("ok")), "dsn": "****"})
        return 0
    finally:
        await repo.close()

async def cmd_registry_device_upsert(args: argparse.Namespace) -> int:
    if not PgRegistryRepository or not RegistryConfig:
        _eprint("Registry module is unavailable")
        return 2
    dsn = args.dsn or _maybe_env("PIC_DB_DSN")
    if not dsn:
        _eprint("Missing DSN: pass --dsn or set PIC_DB_DSN")
        return 2
    repo = PgRegistryRepository(RegistryConfig(dsn=dsn, echo=args.sql_echo))
    try:
        payload = {
            "tenant_id": args.tenant_id,
            "manufacturer_id": args.manufacturer_id,
            "model_id": args.model_id,
            "device_uid": args.device_uid,
            "serial_number": args.serial_number,
            "status": args.status,
            "labels": json.loads(args.labels) if args.labels else {},
            "location": json.loads(args.location) if args.location else {},
        }
        res = await repo.upsert_device(**payload)
        _json_dump(res)
        return 0
    except ConflictError as e:  # type: ignore
        _eprint(f"Conflict: {e}")
        return 3
    except Exception as e:
        _eprint(f"Error: {e}")
        return 1
    finally:
        await repo.close()

async def cmd_registry_device_get(args: argparse.Namespace) -> int:
    if not PgRegistryRepository or not RegistryConfig:
        _eprint("Registry module is unavailable")
        return 2
    dsn = args.dsn or _maybe_env("PIC_DB_DSN")
    if not dsn:
        _eprint("Missing DSN: pass --dsn or set PIC_DB_DSN")
        return 2
    repo = PgRegistryRepository(RegistryConfig(dsn=dsn, echo=args.sql_echo))
    try:
        res = await repo.get_device_by_uid(args.tenant_id, args.device_uid)
        _json_dump(res)
        return 0
    except NotFoundError:  # type: ignore
        _eprint("Not found")
        return 4
    finally:
        await repo.close()

# --- telemetry ---

def _to_series_points(rows: List[Mapping[str, Any]], ts_field: str, values_field: str) -> List[Any]:
    pts: List[Any] = []
    for r in rows:
        ts_raw = r.get(ts_field)
        vals = r.get(values_field)
        if ts_raw is None or not isinstance(vals, Mapping):
            continue
        ts = _ensure_tz(str(ts_raw))
        if SeriesPoint is None:
            raise RuntimeError("Telemetry module not available")
        pts.append(SeriesPoint(ts=ts, values={k: float(v) for k, v in vals.items()}))
    return pts

async def cmd_telemetry_aggregate(args: argparse.Namespace) -> int:
    if aggregate_timeseries is None or AggregationSpec is None:
        _eprint("Telemetry module is unavailable")
        return 2
    rows = _read_json_or_ndjson(args.input)
    pts = _to_series_points(rows, ts_field=args.ts_field, values_field=args.values_field)
    spec = AggregationSpec(
        funcs=[s.strip() for s in args.funcs.split(",") if s.strip()],
        fields=[s.strip() for s in args.fields.split(",")] if args.fields != "*" else ["*"],
        name_pattern=args.name_pattern,
    )
    aggs = aggregate_timeseries(pts, args.interval, spec)
    if args.fill and args.fill != "none":
        aggs = fill_missing_buckets(aggs, args.interval, strategy=args.fill)
    out = [{"ts": a.ts.isoformat(), "values": a.values} for a in aggs]
    _json_dump(out)
    return 0

# --- video ---

async def cmd_video_probe(args: argparse.Namespace) -> int:
    if FFmpegBridge is None:
        _eprint("Video module is unavailable")
        return 2
    bridge = FFmpegBridge(BridgeConfig())
    meta = await bridge.probe(args.src)
    _json_dump(meta)
    return 0

async def cmd_video_transcode(args: argparse.Namespace) -> int:
    if FFmpegBridge is None:
        _eprint("Video module is unavailable")
        return 2
    tcfg = TranscodeConfig(  # type: ignore
        video_codec=args.vcodec,
        audio_codec=args.acodec,
        crf=args.crf,
        preset=args.preset,
        movflags_faststart=True,
        copy_if_compatible=not args.no_copy_if_compatible,
    )
    bridge = FFmpegBridge(BridgeConfig())
    def progress(p: Dict[str, Any]) -> None:
        _eprint(json.dumps(p))
    await bridge.transcode_to_mp4(args.src, args.dst, tcfg=tcfg, start_at=args.start, duration=args.duration, progress_cb=progress)
    _json_dump({"ok": True, "dst": str(args.dst)})
    return 0

async def cmd_video_hls(args: argparse.Namespace) -> int:
    if FFmpegBridge is None:
        _eprint("Video module is unavailable")
        return 2
    bridge = FFmpegBridge(BridgeConfig())
    tcfg = TranscodeConfig(preset=args.preset, crf=args.crf)  # type: ignore
    hcfg = HLSConfig(segment_time=args.seg, playlist_size=args.pl_size, fmp4=args.fmp4)  # type: ignore
    def progress(p: Dict[str, Any]) -> None:
        _eprint(json.dumps(p))
    master = await bridge.hls_segment(args.src, args.out_dir, tcfg=tcfg, hcfg=hcfg, progress_cb=progress)
    _json_dump({"ok": True, "master": str(master)})
    return 0

async def cmd_video_thumbs(args: argparse.Namespace) -> int:
    if FFmpegBridge is None:
        _eprint("Video module is unavailable")
        return 2
    bridge = FFmpegBridge(BridgeConfig())
    tcfg = ThumbnailConfig(interval_seconds=args.interval, width=args.width, height=args.height, start_offset_seconds=args.start)  # type: ignore
    files = await bridge.thumbnails(args.src, args.out_dir, tcfg=tcfg)
    _json_dump({"ok": True, "files": [str(p) for p in files]})
    return 0

async def cmd_video_rtsp2rtmp(args: argparse.Namespace) -> int:
    if FFmpegBridge is None:
        _eprint("Video module is unavailable")
        return 2
    bridge = FFmpegBridge(BridgeConfig())
    def progress(p: Dict[str, Any]) -> None:
        _eprint(json.dumps(p))
    await bridge.rtsp_to_rtmp(args.rtsp, args.rtmp, copy_codecs=not args.transcode, progress_cb=progress)
    _json_dump({"ok": True})
    return 0

# --- twin ---

async def cmd_twin_sync_run(args: argparse.Namespace) -> int:
    if TwinSynchronizer is None or SynchronizerConfig is None:
        _eprint("Twin module is unavailable")
        return 2

    # TwinStore
    if args.twin_store:
        TwinStoreClass = _import_from_string(args.twin_store)
        twin_store = TwinStoreClass()
    else:
        twin_store = InMemoryTwinStore()  # type: ignore

    # Adapters (must be provided)
    if not args.twin_adapter or not args.physical_adapter or not args.entity_source:
        _eprint("Provide --twin-adapter, --physical-adapter and --entity-source (import path to classes)")
        return 2
    TwinAdapterClass = _import_from_string(args.twin_adapter)
    PhysicalAdapterClass = _import_from_string(args.physical_adapter)
    EntitySourceClass = _import_from_string(args.entity_source)

    twin_adapter = TwinAdapterClass()
    physical_adapter = PhysicalAdapterClass()
    entity_source = EntitySourceClass()

    cfg = SynchronizerConfig(
        tenant_id=args.tenant_id,
        concurrency=args.concurrency,
        batch_size=args.batch,
        full_resync_interval=args.full_resync,
        lease_ttl=args.lease_ttl,
        max_retries=args.max_retries,
        base_backoff=args.base_backoff,
        backoff_factor=args.backoff_factor,
        max_backoff=args.max_backoff,
        apply_desired_policy=args.apply_desired_policy,
    )
    sync = TwinSynchronizer(cfg, twin_store, twin_adapter, physical_adapter, entity_source)

    # Run until SIGINT/SIGTERM
    await _graceful(sync.run())
    _json_dump({"ok": True})
    return 0

# --- observability ---

def cmd_obs_log_test(_: argparse.Namespace) -> int:
    log = get_logger("pic.cli.test")
    set_context(tenant_id="t-test", request_id="r-123")
    log.info("test info", extra={"k": 1})
    try:
        1 / 0
    except Exception:
        import logging as _l
        _l.getLogger("pic.cli.test").exception("test exception")
    _json_dump({"ok": True})
    return 0


# =============================================================================
# Argparse definitions
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pic", description="Physical Integration Core CLI")
    p.add_argument("--config", help="Path to config (yaml/json/env-like)", default=os.getenv("PIC_CONFIG"))
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"), help="Log level")
    p.add_argument("--log-json", action=argparse.BooleanOptionalAction, default=True, help="Structured JSON logs")
    p.add_argument("--env", default=os.getenv("ENV", "dev"), help="Environment label for logs")
    p.add_argument("--service", default="pic-cli", help="Service name for logs")
    p.add_argument("--request-id", default=os.getenv("REQUEST_ID"), help="Request/Correlation ID for logs")

    sp = p.add_subparsers(dest="cmd", required=True)

    # registry
    pr = sp.add_parser("registry", help="Registry operations")
    sr = pr.add_subparsers(dest="sub", required=True)

    prh = sr.add_parser("health", help="DB health check")
    prh.add_argument("--dsn", help="PostgreSQL DSN (or PIC_DB_DSN env)")
    prh.add_argument("--pool-size", type=int, default=10)
    prh.add_argument("--sql-echo", action="store_true")
    prh.set_defaults(func=cmd_registry_health)

    pru = sr.add_parser("device-upsert", help="Upsert device")
    pru.add_argument("--dsn", help="PostgreSQL DSN (or PIC_DB_DSN env)")
    pru.add_argument("--tenant-id", required=True)
    pru.add_argument("--manufacturer-id", required=True)
    pru.add_argument("--model-id", required=True)
    pru.add_argument("--device-uid", required=True)
    pru.add_argument("--serial-number")
    pru.add_argument("--status", default="provisioned")
    pru.add_argument("--labels", help='JSON map')
    pru.add_argument("--location", help='JSON map')
    pru.add_argument("--sql-echo", action="store_true")
    pru.set_defaults(func=cmd_registry_device_upsert)

    prg = sr.add_parser("device-get", help="Get device by uid")
    prg.add_argument("--dsn", help="PostgreSQL DSN (or PIC_DB_DSN env)")
    prg.add_argument("--tenant-id", required=True)
    prg.add_argument("--device-uid", required=True)
    prg.add_argument("--sql-echo", action="store_true")
    prg.set_defaults(func=cmd_registry_device_get)

    # telemetry
    pt = sp.add_parser("telemetry", help="Telemetry utilities")
    st = pt.add_subparsers(dest="sub", required=True)

    pta = st.add_parser("aggregate", help="Aggregate/Downsample timeseries (JSON or NDJSON input)")
    pta.add_argument("--input", help="Path to JSON/NDJSON file or - for stdin", default="-")
    pta.add_argument("--interval", required=True, help="e.g. 10s,1m,5m,1h")
    pta.add_argument("--funcs", required=True, help="Comma list: avg,min,max,sum,count,stddev,p50,p90,p95,p99,rate,ewma")
    pta.add_argument("--fields", default="*", help="Comma list or *")
    pta.add_argument("--name-pattern", default="{field}_{func}")
    pta.add_argument("--fill", choices=["none", "zero", "ffill"], default="none")
    pta.add_argument("--ts-field", default="ts")
    pta.add_argument("--values-field", default="values")
    pta.set_defaults(func=cmd_telemetry_aggregate)

    # video
    pv = sp.add_parser("video", help="FFmpeg tasks")
    sv = pv.add_subparsers(dest="sub", required=True)

    pvp = sv.add_parser("probe", help="ffprobe JSON metadata")
    pvp.add_argument("src", help="Source file/URL")
    pvp.set_defaults(func=cmd_video_probe)

    pvt = sv.add_parser("transcode", help="Transcode to MP4")
    pvt.add_argument("src")
    pvt.add_argument("dst")
    pvt.add_argument("--vcodec", default="libx264")
    pvt.add_argument("--acodec", default="aac")
    pvt.add_argument("--crf", type=int, default=23)
    pvt.add_argument("--preset", default="veryfast")
    pvt.add_argument("--start", type=float)
    pvt.add_argument("--duration", type=float)
    pvt.add_argument("--no-copy-if-compatible", action="store_true")
    pvt.set_defaults(func=cmd_video_transcode)

    pvh = sv.add_parser("hls", help="Produce HLS (single variant)")
    pvh.add_argument("src")
    pvh.add_argument("out_dir")
    pvh.add_argument("--preset", default="veryfast")
    pvh.add_argument("--crf", type=int, default=23)
    pvh.add_argument("--seg", type=int, default=6)
    pvh.add_argument("--pl-size", type=int, default=10)
    pvh.add_argument("--fmp4", action="store_true")
    pvh.set_defaults(func=cmd_video_hls)

    pvn = sv.add_parser("thumbnails", help="Extract thumbnails")
    pvn.add_argument("src")
    pvn.add_argument("out_dir")
    pvn.add_argument("--interval", type=int, default=10)
    pvn.add_argument("--width", type=int)
    pvn.add_argument("--height", type=int)
    pvn.add_argument("--start", type=int, default=0)
    pvn.set_defaults(func=cmd_video_thumbs)

    pvr = sv.add_parser("rtsp2rtmp", help="Push RTSP to RTMP")
    pvr.add_argument("--rtsp", required=True)
    pvr.add_argument("--rtmp", required=True)
    pvr.add_argument("--transcode", action="store_true", help="If set, transcode instead of copy")
    pvr.set_defaults(func=cmd_video_rtsp2rtmp)

    # twin
    ptw = sp.add_parser("twin", help="Digital Twin operations")
    stw = ptw.add_subparsers(dest="sub", required=True)

    ptr = stw.add_parser("sync-run", help="Run synchronizer until stopped")
    ptr.add_argument("--tenant-id", required=True)
    ptr.add_argument("--twin-adapter", required=True, help="Import path to TwinPlatformAdapter class, e.g. 'pkg.mod:MyAdapter'")
    ptr.add_argument("--physical-adapter", required=True, help="Import path to PhysicalStateAdapter class")
    ptr.add_argument("--entity-source", required=True, help="Import path to EntitySource class")
    ptr.add_argument("--twin-store", help="Import path to TwinStore class (default in-memory)")
    ptr.add_argument("--concurrency", type=int, default=8)
    ptr.add_argument("--batch", type=int, default=200)
    from datetime import timedelta
    ptr.add_argument("--full-resync", type=lambda s: timedelta(seconds=int(s)), default=timedelta(minutes=15), help="Seconds")
    ptr.add_argument("--lease-ttl", type=lambda s: timedelta(seconds=int(s)), default=timedelta(minutes=5), help="Seconds")
    ptr.add_argument("--max-retries", type=int, default=5)
    ptr.add_argument("--base-backoff", type=float, default=0.3)
    ptr.add_argument("--backoff-factor", type=float, default=2.0)
    ptr.add_argument("--max-backoff", type=float, default=15.0)
    ptr.add_argument("--apply-desired-policy", action="store_true")
    ptr.set_defaults(func=cmd_twin_sync_run)

    # observability
    po = sp.add_parser("obs", help="Observability helpers")
    so = po.add_subparsers(dest="sub", required=True)
    pot = so.add_parser("log-test", help="Emit test logs")
    pot.set_defaults(func=cmd_obs_log_test)

    return p


# =============================================================================
# Main
# =============================================================================

def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(list(argv))

    # Load config (optional) and configure logging
    cfg = _load_config_file(args.config) if args.config else {}
    log_cfg = LoggingConfig(
        service=args.service or cfg.get("service", "pic-cli"),
        env=args.env or cfg.get("env", "dev"),
        level=args.log_level or cfg.get("log_level", "INFO"),
        json_output=bool(args.log_json if args.log_json is not None else cfg.get("log_json", True)),
    )
    configure_logging(log_cfg)
    if args.request_id:
        set_context(request_id=args.request_id)

    # Dispatch
    func: Optional[Callable[[argparse.Namespace], Union[int, Awaitable[int]]]] = getattr(args, "func", None)
    if not func:
        parser.print_help()
        return 2

    try:
        if asyncio.iscoroutinefunction(func):  # type: ignore
            rc = asyncio.run(func(args))  # type: ignore[arg-type]
        else:
            # Some funcs are sync (e.g., obs log-test)
            rc = func(args)  # type: ignore[misc]
        return int(rc) if isinstance(rc, int) else 0
    except KeyboardInterrupt:
        _eprint("Interrupted")
        return 130
    except SystemExit as e:
        return int(e.code)
    except Exception as e:
        _eprint(f"Unhandled error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
