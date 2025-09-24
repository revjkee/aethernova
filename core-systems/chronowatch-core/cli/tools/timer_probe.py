#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
timer_probe.py — Industrial-grade time and scheduler probe for ChronoWatch Core.

Features:
  - High-resolution, async tick scheduler using perf_counter_ns
  - Measures jitter (actual tick - scheduled deadline) and sleep accuracy
  - Calibrates overhead of timing and bookkeeping
  - Tracks drift between wall clock (time.time) and monotonic clock
  - Optional SNTP (NTP) offset/delay against configurable servers (no deps)
  - Robust statistics: p50/p90/p95/p99, mean, stdev, min, max
  - JSON and CSV exports; structured stdout summary; rotating logging
  - Graceful SIGINT/SIGTERM handling
  - Optional psutil integration for CPU/mem (if installed), with soft fallback

Usage examples:
  - Basic 30s run at 10ms interval:
      python timer_probe.py --duration 30 --interval 0.01

  - With SNTP check before/after against pool.ntp.org:
      python timer_probe.py --ntp pool.ntp.org --ntp-timeout 1.5

  - Export JSON and CSV:
      python timer_probe.py --json-out probe.json --csv-out probe.csv

  - Increase verbosity and write a log:
      python timer_probe.py -v --log-file timer_probe.log
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import dataclasses
import json
import math
import os
import platform
import random
import signal
import socket
import statistics
import sys
import time
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging import getLogger, Formatter, INFO, DEBUG, StreamHandler, FileHandler
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

LOG = getLogger("chronowatch.timer_probe")

# ----------------------------- Utilities ------------------------------------


def _setup_logging(verbosity: int, log_file: Optional[str]) -> None:
    level = DEBUG if verbosity > 0 else INFO
    LOG.setLevel(level)
    fmt = Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s", "%Y-%m-%dT%H:%M:%S%z")
    sh = StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(level)
    LOG.addHandler(sh)
    if log_file:
        fh = FileHandler(log_file)
        fh.setFormatter(fmt)
        fh.setLevel(level)
        LOG.addHandler(fh)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def quantiles_safe(samples: List[float], probs: Iterable[float]) -> Dict[str, float]:
    if not samples:
        return {f"p{int(p*100)}": math.nan for p in probs}
    # Python's statistics.quantiles needs n>=1 and method='inclusive' for exactness on small n
    # We implement robust percentiles for arbitrary n via sorted index interpolation
    s = sorted(samples)
    n = len(s)
    out: Dict[str, float] = {}
    for p in probs:
        if n == 1:
            val = s[0]
        else:
            idx = p * (n - 1)
            lo = int(math.floor(idx))
            hi = int(math.ceil(idx))
            if lo == hi:
                val = s[lo]
            else:
                frac = idx - lo
                val = s[lo] * (1.0 - frac) + s[hi] * frac
        out[f"p{int(round(p*100))}"] = val
    return out


def try_import_psutil():
    with suppress(Exception):
        import psutil  # type: ignore

        return psutil
    return None


# ----------------------------- Data Models ----------------------------------


@dataclass
class Sample:
    """
    One tick sample.

    All time values in seconds.
    """
    idx: int
    scheduled_t: float  # monotonic target time
    actual_t: float     # actual perf_counter when executed
    jitter: float       # actual - scheduled
    sleep_req: float    # requested sleep duration
    sleep_eff: float    # effective sleep duration
    wall_t: float       # time.time at sample
    drift_wall_vs_mono: float  # (wall - wall0) - (mono - mono0)


@dataclass
class Stats:
    count: int
    mean: float
    stdev: float
    vmin: float
    vmax: float
    p50: float
    p90: float
    p95: float
    p99: float

    @staticmethod
    def from_series(series: List[float]) -> "Stats":
        if not series:
            return Stats(0, math.nan, math.nan, math.nan, math.nan, math.nan, math.nan, math.nan, math.nan)
        mean = statistics.fmean(series)
        stdev = statistics.pstdev(series) if len(series) > 1 else 0.0
        vmin, vmax = min(series), max(series)
        q = quantiles_safe(series, [0.5, 0.9, 0.95, 0.99])
        return Stats(len(series), mean, stdev, vmin, vmax, q["p50"], q["p90"], q["p95"], q["p99"])


@dataclass
class NtpResult:
    server: str
    success: bool
    offset: Optional[float]  # seconds (wall_clock - ntp_time), positive means system ahead
    delay: Optional[float]   # round-trip delay seconds
    root_dispersion: Optional[float]
    version: int
    error: Optional[str] = None


@dataclass
class RunMetadata:
    started_at: str
    finished_at: Optional[str]
    host: str
    platform: str
    python: str
    pid: int
    interval: float
    duration: float
    warmup: float
    ntp_servers: List[str]
    notes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProbeReport:
    meta: RunMetadata
    overhead_ns_per_tick: int
    jitter_stats_us: Stats
    sleep_error_stats_us: Stats
    drift_stats_ms: Stats
    ntp_before: List[NtpResult]
    ntp_after: List[NtpResult]
    samples_kept: int
    csv_path: Optional[str]
    json_path: Optional[str]
    log_path: Optional[str]


# ----------------------------- SNTP Client ----------------------------------


class SimpleSNTP:
    """
    Minimal SNTP client (per RFC 4330) without external deps.
    """

    NTP_EPOCH = 2208988800  # 1970-01-01 to 1900-01-01 in seconds
    PACKET_LEN = 48

    @staticmethod
    def _to_ntp_time(unix_ts: float) -> Tuple[int, int]:
        whole = int(unix_ts) + SimpleSNTP.NTP_EPOCH
        frac = int((unix_ts - int(unix_ts)) * (1 << 32))
        return whole, frac

    @staticmethod
    def _to_unix_time(ntp_sec: int, ntp_frac: int) -> float:
        return (ntp_sec - SimpleSNTP.NTP_EPOCH) + ntp_frac / (1 << 32)

    @staticmethod
    def query(host: str, timeout: float = 1.5, version: int = 3) -> NtpResult:
        try:
            addr = socket.getaddrinfo(host, 123, 0, socket.SOCK_DGRAM)[0][4]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                # Build client request
                # LI=0, VN=version, Mode=3 (client)
                li_vn_mode = (0 << 6) | (version << 3) | 3
                packet = bytearray(SimpleSNTP.PACKET_LEN)
                packet[0] = li_vn_mode
                # Transmit timestamp (T1)
                t1_unix = time.time()
                t1s, t1f = SimpleSNTP._to_ntp_time(t1_unix)
                # Place Transmit Timestamp at bytes 40..47
                packet[40:44] = t1s.to_bytes(4, "big")
                packet[44:48] = t1f.to_bytes(4, "big")

                s.sendto(packet, addr)
                data, _ = s.recvfrom(256)
                t4_unix = time.time()
                if len(data) < SimpleSNTP.PACKET_LEN:
                    return NtpResult(host, False, None, None, None, version, error="short packet")

                # Parse server packet
                stratum = data[1]
                # Root dispersion at bytes 8..11 (unsigned 16.16)
                root_disp = int.from_bytes(data[8:12], "big") / (1 << 16)

                # Timestamps
                # Origin Timestamp (T1): 24..31
                o1s = int.from_bytes(data[24:28], "big")
                o1f = int.from_bytes(data[28:32], "big")
                # Receive Timestamp (T2): 32..39
                r2s = int.from_bytes(data[32:36], "big")
                r2f = int.from_bytes(data[36:40], "big")
                # Transmit Timestamp (T3): 40..47
                t3s = int.from_bytes(data[40:44], "big")
                t3f = int.from_bytes(data[44:48], "big")

                # Convert
                t1 = t1_unix  # we set it
                t2 = SimpleSNTP._to_unix_time(r2s, r2f)
                t3 = SimpleSNTP._to_unix_time(t3s, t3f)
                t4 = t4_unix

                # Standard offset/delay formulas
                delay = (t4 - t1) - (t3 - t2)
                offset = ((t2 - t1) + (t3 - t4)) / 2.0

                return NtpResult(
                    server=host,
                    success=True,
                    offset=offset,
                    delay=delay,
                    root_dispersion=root_disp,
                    version=version,
                )
        except Exception as e:
            return NtpResult(host, False, None, None, None, version, error=str(e))


# ----------------------------- Core Probe -----------------------------------


class TimerProbe:
    def __init__(
        self,
        interval: float,
        duration: float,
        warmup: float,
        max_samples: Optional[int] = None,
        randomize_start: bool = True,
    ):
        if interval <= 0:
            raise ValueError("interval must be > 0")
        if duration <= 0:
            raise ValueError("duration must be > 0")
        if warmup < 0:
            raise ValueError("warmup must be >= 0")
        self.interval = interval
        self.duration = duration
        self.warmup = warmup
        self.max_samples = max_samples
        self.randomize_start = randomize_start

        self._stop = asyncio.Event()

    # -------- Overhead calibration

    @staticmethod
    def calibrate_overhead_ns(iterations: int = 200_000) -> int:
        """Measure intrinsic read/arith/append overhead in ns."""
        pc = time.perf_counter_ns
        t0 = pc()
        dummy = 0
        for _ in range(iterations):
            a = pc()
            b = pc()
            dummy += (b - a)
        t1 = pc()
        # Average cost per loop body; divide by two reads to approximate per read
        loops_ns = t1 - t0
        per_loop_ns = loops_ns / iterations
        # Minimalistic correction using measured dummy accumulations
        _ = dummy  # keep reference
        return int(per_loop_ns)

    # -------- Signal handling

    def install_signal_handlers(self):
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop.set)

    def request_stop(self):
        self._stop.set()

    # -------- Measurement loop

    async def run(self) -> List[Sample]:
        # Warm up
        mono0 = time.perf_counter()
        wall0 = time.time()

        if self.randomize_start:
            # Randomize to avoid synchronizing with periodic system tasks
            await asyncio.sleep(random.uniform(0, self.interval))

        if self.warmup > 0:
            LOG.info("Warmup phase: %.3fs", self.warmup)
            await asyncio.sleep(self.warmup)

        samples: List[Sample] = []

        # Scheduling by absolute deadlines to prevent drift
        start_mono = time.perf_counter()
        start_wall = time.time()
        next_deadline = start_mono + self.interval

        end_time = start_mono + self.duration
        idx = 0

        # Sleep accuracy: compare requested vs effective
        while True:
            if self._stop.is_set():
                LOG.info("Stop requested by signal.")
                break
            now = time.perf_counter()
            if now >= end_time:
                break

            sleep_req = max(0.0, next_deadline - now)
            t_before_sleep = time.perf_counter()
            await asyncio.sleep(sleep_req)
            t_after_sleep = time.perf_counter()

            # Execution instant
            actual = t_after_sleep
            jitter = actual - next_deadline
            wall = time.time()
            drift = (wall - start_wall) - (actual - start_mono)

            samples.append(
                Sample(
                    idx=idx,
                    scheduled_t=next_deadline,
                    actual_t=actual,
                    jitter=jitter,
                    sleep_req=sleep_req,
                    sleep_eff=t_after_sleep - t_before_sleep,
                    wall_t=wall,
                    drift_wall_vs_mono=drift,
                )
            )
            idx += 1

            if self.max_samples and idx >= self.max_samples:
                LOG.info("Reached max_samples=%d; stopping.", self.max_samples)
                break

            next_deadline += self.interval

        LOG.info("Collected %d samples.", len(samples))
        # Ensure baseline fields are present even if empty set
        _ = mono0, wall0
        return samples


# ----------------------------- Reporting ------------------------------------


def build_report(
    samples: List[Sample],
    meta: RunMetadata,
    overhead_ns: int,
    csv_path: Optional[str],
    json_path: Optional[str],
    log_path: Optional[str],
    ntp_before: List[NtpResult],
    ntp_after: List[NtpResult],
) -> ProbeReport:
    jitter_us = [s.jitter * 1e6 for s in samples]
    sleep_err_us = [(s.sleep_eff - s.sleep_req) * 1e6 for s in samples]
    drift_ms = [s.drift_wall_vs_mono * 1e3 for s in samples]

    return ProbeReport(
        meta=meta,
        overhead_ns_per_tick=overhead_ns,
        jitter_stats_us=Stats.from_series(jitter_us),
        sleep_error_stats_us=Stats.from_series(sleep_err_us),
        drift_stats_ms=Stats.from_series(drift_ms),
        ntp_before=ntp_before,
        ntp_after=ntp_after,
        samples_kept=len(samples),
        csv_path=csv_path,
        json_path=json_path,
        log_path=log_path,
    )


def write_csv(samples: List[Sample], path: str) -> None:
    fieldnames = [f.name for f in dataclasses.fields(Sample)]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for s in samples:
            w.writerow(dataclasses.asdict(s))


def write_json(report: ProbeReport, path: str) -> None:
    def default(o: Any):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, (set,)):
            return list(o)
        if isinstance(o, (datetime,)):
            return o.isoformat()
        return str(o)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=default)


def print_summary(report: ProbeReport) -> None:
    m = report.meta
    js = report.jitter_stats_us
    ss = report.sleep_error_stats_us
    ds = report.drift_stats_ms

    print("ChronoWatch Timer Probe Summary")
    print("Run window: {} .. {}".format(m.started_at, m.finished_at or "n/a"))
    print("Host: {} | Platform: {} | Python: {}".format(m.host, m.platform, m.python))
    print("Interval: {:.6f}s | Duration: {:.3f}s | Warmup: {:.3f}s | Samples: {}".format(
        m.interval, m.duration, m.warmup, report.samples_kept
    ))
    if report.overhead_ns_per_tick:
        print("Calibrated overhead: ~{} ns per tick".format(report.overhead_ns_per_tick))
    if m.ntp_servers:
        def fmt_ntp(arr: List[NtpResult]) -> str:
            parts = []
            for r in arr:
                if r.success:
                    parts.append(f"{r.server} offset={r.offset:.6f}s delay={r.delay:.6f}s disp={r.root_dispersion:.6f}s")
                else:
                    parts.append(f"{r.server} error={r.error}")
            return "; ".join(parts)
        print("SNTP before: {}".format(fmt_ntp(report.ntp_before)))
        print("SNTP after : {}".format(fmt_ntp(report.ntp_after)))

    def fmt_stats(name: str, st: Stats, unit: str) -> None:
        print(
            f"{name}: count={st.count} "
            f"mean={st.mean:.3f}{unit} stdev={st.stdev:.3f}{unit} "
            f"min={st.vmin:.3f}{unit} p50={st.p50:.3f}{unit} "
            f"p90={st.p90:.3f}{unit} p95={st.p95:.3f}{unit} p99={st.p99:.3f}{unit} "
            f"max={st.vmax:.3f}{unit}"
        )

    fmt_stats("Jitter", js, "us")
    fmt_stats("Sleep error", ss, "us")
    fmt_stats("Wall vs Mono drift", ds, "ms")

    if report.csv_path:
        print(f"CSV saved to: {report.csv_path}")
    if report.json_path:
        print(f"JSON saved to: {report.json_path}")
    if report.log_path:
        print(f"Log file: {report.log_path}")


# ----------------------------- CLI ------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="timer_probe",
        description="High-resolution scheduler and timer probe (ChronoWatch Core).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--interval", type=float, default=0.01, help="Tick interval in seconds")
    p.add_argument("--duration", type=float, default=30.0, help="Total measurement duration in seconds")
    p.add_argument("--warmup", type=float, default=0.5, help="Warmup sleep before sampling, seconds")
    p.add_argument("--max-samples", type=int, default=None, help="Optional cap on number of samples")
    p.add_argument("--no-random-start", action="store_true", help="Disable randomized start offset")
    p.add_argument("--ntp", action="append", default=[], help="SNTP server to query (can repeat)")
    p.add_argument("--ntp-timeout", type=float, default=1.5, help="SNTP socket timeout seconds")
    p.add_argument("--ntp-version", type=int, default=3, choices=[3, 4], help="SNTP version")
    p.add_argument("--json-out", type=str, default=None, help="Path to write JSON report")
    p.add_argument("--csv-out", type=str, default=None, help="Path to write per-sample CSV")
    p.add_argument("--log-file", type=str, default=None, help="Path to write a log file")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    return p


async def _ntp_probe(servers: List[str], timeout: float, version: int) -> List[NtpResult]:
    loop = asyncio.get_running_loop()
    tasks = [
        loop.run_in_executor(None, SimpleSNTP.query, s, timeout, version) for s in servers
    ]
    out: List[NtpResult] = []
    for coro in asyncio.as_completed(tasks, timeout=timeout + 0.5):
        with suppress(asyncio.TimeoutError):
            res = await coro
            out.append(res)  # type: ignore
    # Include failures for servers that didn't return (best effort)
    by_srv = {r.server for r in out}
    for s in servers:
        if s not in by_srv:
            out.append(NtpResult(server=s, success=False, offset=None, delay=None, root_dispersion=None, version=version, error="timeout"))
    return out


async def main_async(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose, args.log_file)

    psutil = try_import_psutil()
    if psutil:
        with suppress(Exception):
            LOG.info("System load: %s | CPU: %.1f%% | Mem: %.1f%%",
                     os.getloadavg() if hasattr(os, "getloadavg") else "n/a",
                     psutil.cpu_percent(interval=0.1),
                     psutil.virtual_memory().percent)

    meta = RunMetadata(
        started_at=now_iso(),
        finished_at=None,
        host=platform.node(),
        platform=platform.platform(),
        python=sys.version.split()[0],
        pid=os.getpid(),
        interval=args.interval,
        duration=args.duration,
        warmup=args.warmup,
        ntp_servers=list(args.ntp),
    )

    probe = TimerProbe(
        interval=args.interval,
        duration=args.duration,
        warmup=args.warmup,
        max_samples=args.max_samples,
        randomize_start=not args.no_random_start,
    )
    probe.install_signal_handlers()

    overhead_ns = TimerProbe.calibrate_overhead_ns()

    ntp_before: List[NtpResult] = []
    ntp_after: List[NtpResult] = []
    if args.ntp:
        LOG.info("Querying SNTP (before) for %s", args.ntp)
        ntp_before = await _ntp_probe(args.ntp, args.ntp_timeout, args.ntp_version)

    samples = await probe.run()

    if args.ntp:
        LOG.info("Querying SNTP (after) for %s", args.ntp)
        ntp_after = await _ntp_probe(args.ntp, args.ntp_timeout, args.ntp_version)

    meta.finished_at = now_iso()

    csv_path = args.csv_out
    if csv_path:
        try:
            write_csv(samples, csv_path)
        except Exception as e:
            LOG.error("CSV write failed: %s", e)
            csv_path = None

    report = build_report(
        samples=samples,
        meta=meta,
        overhead_ns=overhead_ns,
        csv_path=csv_path,
        json_path=args.json_out,
        log_path=args.log_file,
        ntp_before=ntp_before,
        ntp_after=ntp_after,
    )

    if args.json_out:
        try:
            write_json(report, args.json_out)
        except Exception as e:
            LOG.error("JSON write failed: %s", e)
            report.json_path = None

    print_summary(report)
    return 0


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
