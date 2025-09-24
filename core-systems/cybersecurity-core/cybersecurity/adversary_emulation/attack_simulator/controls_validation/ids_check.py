# filepath: cybersecurity-core/cybersecurity/adversary_emulation/attack_simulator/controls_validation/ids_check.py
"""
IDS Controls Validation Harness (industrial-grade)

Назначение:
- Прогон сценариев имитации противника через IDS (по умолчанию Suricata EVE JSON).
- Опциональная инъекция PCAP трафика через tcpreplay.
- Сопоставление фактических алертов с ожиданиями (regex по сигнатуре, уровень severity, IP/порты).
- Метрики качества детекций (TP/FP/FN, Precision/Recall/F1).
- Экспорт отчетов: JSON, Markdown, JUnit XML.
- Строгие таймауты, безопасный запуск subprocess, структурированные логи.

Формат EVE JSON Suricata и его назначение:
- Документация Suricata “EVE — Eve JSON Format / Output”.
  См. официальные источники:
  https://docs.suricata.io/en/latest/output/eve/index.html
  https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
  https://docs.suricata.io/en/suricata-7.0.6/output/eve/eve-json-output.html

Инъекция трафика:
- Утилита tcpreplay (официальные материалы/мануалы).
  https://tcpreplay.appneta.com/  и  https://tcpreplay.appneta.com/wiki/tcpreplay-man.html

Привязка ожиданий к MITRE ATT&CK:
- Официальная база MITRE ATT&CK.
  https://attack.mitre.org/

Пример минимального конфига (JSON/YAML):
{
  "ids": {
    "type": "suricata_eve",
    "eve_file": "/var/log/suricata/eve.json"
  },
  "scenario": {
    "pcap": "/opt/pcaps/test.pcap",
    "iface": "eth0",
    "inject": true
  },
  "expectations": [
    {
      "id": "EXP-1",
      "signature_regex": "ET .* Malicious .*",
      "min_severity": 2,
      "src_ip": null,
      "dst_ip": null,
      "count_min": 1,
      "count_max": null,
      "mitre_techniques": ["T1059", "T1071"],
      "window_before_sec": 5,
      "window_after_sec": 60
    }
  ],
  "timings": {
    "inject_timeout_sec": 120,
    "post_inject_grace_sec": 10,
    "read_timeout_sec": 30
  },
  "reporting": {
    "output_dir": "./reports",
    "write_junit": true,
    "write_markdown": true,
    "write_json": true,
    "fail_on_fn": true
  }
}

Запуск:
python ids_check.py --config path/to/config.json
python ids_check.py --config path/to/config.yaml

Зависимости: стандартная библиотека Python. YAML поддерживается, если установлен PyYAML.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import json
import logging
import os
import re
import shlex
import signal
import statistics
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ----------------------------
# Logging (JSON formatter)
# ----------------------------

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            base["stack_info"] = self.formatStack(record.stack_info)
        # Attach extra dict-like attributes if present
        for k, v in record.__dict__.items():
            if k not in ("name", "msg", "args", "levelname", "levelno",
                         "pathname", "filename", "module", "exc_info",
                         "exc_text", "stack_info", "lineno", "funcName",
                         "created", "msecs", "relativeCreated", "thread",
                         "threadName", "processName", "process"):
                base[k] = v
        return json.dumps(base, ensure_ascii=False)


def _setup_logging(level: str = "INFO") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.setLevel(lvl)
    root.handlers.clear()
    root.addHandler(handler)


log = logging.getLogger("ids_check")


# ----------------------------
# Data structures
# ----------------------------

@dataclass(frozen=True)
class IDSAlert:
    timestamp: dt.datetime
    signature: str
    category: Optional[str]
    severity: Optional[int]
    src_ip: Optional[str]
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    proto: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AlertExpectation:
    id: str
    signature_regex: str
    min_severity: int = 1
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    count_min: int = 1
    count_max: Optional[int] = None
    mitre_techniques: List[str] = field(default_factory=list)
    window_before_sec: int = 0
    window_after_sec: int = 60

    def compile(self) -> re.Pattern:
        return re.compile(self.signature_regex, re.IGNORECASE | re.MULTILINE)


@dataclass
class InjectionResult:
    started_at: dt.datetime
    ended_at: dt.datetime
    returncode: int
    cmd: List[str]
    stdout: str
    stderr: str


@dataclass
class MatchResult:
    expectation: AlertExpectation
    matched_alerts: List[IDSAlert]
    satisfied: bool
    shortfall: int  # how many alerts short to meet count_min (0 if satisfied)


@dataclass
class EvaluationReport:
    started_at: dt.datetime
    ended_at: dt.datetime
    matches: List[MatchResult]
    alerts_seen: List[IDSAlert]
    metrics: Dict[str, Any]
    metadata: Dict[str, Any]


# ----------------------------
# Exceptions
# ----------------------------

class IDSCheckError(Exception):
    pass


class TimeoutError(IDSCheckError):
    pass


# ----------------------------
# Utilities
# ----------------------------

_ISO_TZ_RE = re.compile(r"(.*)([+-]\d{2})(\d{2})$")


def _parse_eve_timestamp(ts: str) -> dt.datetime:
    """
    Suricata EVE 'timestamp' обычно в формате вида "YYYY-MM-DDTHH:MM:SS.ssssss+0000" или с 'Z'.
    Преобразуем к ISO 8601 с двоеточием в смещении.
    """
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    else:
        m = _ISO_TZ_RE.match(ts)
        if m:
            ts = f"{m.group(1)}{m.group(2)}:{m.group(3)}"
    try:
        dt_obj = dt.datetime.fromisoformat(ts)
    except ValueError as e:
        raise IDSCheckError(f"Cannot parse timestamp: {ts}") from e
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=dt.timezone.utc)
    return dt_obj.astimezone(dt.timezone.utc)


def _ensure_utc(t: dt.datetime) -> dt.datetime:
    if t.tzinfo is None:
        return t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc)


def _within_window(ts: dt.datetime, since: dt.datetime, until: dt.datetime) -> bool:
    ts = _ensure_utc(ts)
    return since <= ts <= until


def _safe_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None


def _mkdir_p(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _load_config(path: Path) -> Dict[str, Any]:
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # optional
        except Exception as e:
            raise IDSCheckError("YAML config requested but PyYAML is not installed") from e
        return yaml.safe_load(content) or {}
    # default JSON
    return json.loads(content)


# ----------------------------
# IDS Adapter (Suricata EVE)
# ----------------------------

class IDSAdapter:
    async def health_check(self) -> None:
        raise NotImplementedError

    async def fetch_alerts(self, since: dt.datetime, until: dt.datetime) -> List[IDSAlert]:
        raise NotImplementedError

    async def clear_state(self) -> None:
        return None


class SuricataEveAdapter(IDSAdapter):
    """
    Чтение событий EVE JSON Suricata из одного файла (ротация вне зоны ответственности).
    Фильтруем event_type=alert и возвращаем IDSAlert.
    См. официальные документы Suricata по EVE JSON. 
    """

    def __init__(self, eve_file: Union[str, Path]) -> None:
        self.eve_file = Path(eve_file)

    async def health_check(self) -> None:
        if not self.eve_file.exists():
            raise IDSCheckError(f"EVE file not found: {self.eve_file}")
        if not self.eve_file.is_file():
            raise IDSCheckError(f"EVE path is not a file: {self.eve_file}")

    async def fetch_alerts(self, since: dt.datetime, until: dt.datetime) -> List[IDSAlert]:
        since = _ensure_utc(since)
        until = _ensure_utc(until)
        results: List[IDSAlert] = []

        # Stream line-by-line to handle large files
        with self.eve_file.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line[0] not in "{[":
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                etype = obj.get("event_type")
                if etype != "alert":
                    continue

                ts_raw = obj.get("timestamp") or obj.get("ts")
                if not ts_raw:
                    continue

                try:
                    ts = _parse_eve_timestamp(ts_raw)
                except IDSCheckError:
                    continue

                if not _within_window(ts, since, until):
                    continue

                alert = obj.get("alert") or {}
                sig = alert.get("signature") or ""
                cat = alert.get("category")
                sev = _safe_int(alert.get("severity"))
                src_ip = obj.get("src_ip")
                dst_ip = obj.get("dest_ip") or obj.get("dst_ip")
                src_port = _safe_int(obj.get("src_port"))
                dst_port = _safe_int(obj.get("dest_port") or obj.get("dst_port"))
                proto = obj.get("proto")
                results.append(IDSAlert(
                    timestamp=ts, signature=sig, category=cat, severity=sev,
                    src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
                    proto=proto, raw=obj
                ))

        log.info("eve_fetch_done", count=len(results), since=since.isoformat(), until=until.isoformat())
        return results


# ----------------------------
# Traffic injection (tcpreplay)
# ----------------------------

class TrafficInjector:
    """
    Инъекция PCAP через tcpreplay. Требует установленный бинарь tcpreplay.
    Официальное описание tcpreplay см. в источниках.
    """

    def __init__(self, executable: str = "tcpreplay") -> None:
        self.executable = executable

    async def inject_pcap(
        self,
        pcap_path: Union[str, Path],
        iface: str,
        timeout_sec: int = 120,
        rate_mbps: Optional[float] = None,
        pps: Optional[int] = None,
        extra_args: Optional[List[str]] = None,
    ) -> InjectionResult:
        pcap = Path(pcap_path)
        if not pcap.exists() or not pcap.is_file():
            raise IDSCheckError(f"PCAP not found: {pcap}")

        cmd: List[str] = [self.executable, "-i", iface]
        if rate_mbps is not None:
            cmd += ["--mbps", str(rate_mbps)]
        if pps is not None:
            cmd += ["--pps", str(pps)]
        if extra_args:
            cmd += list(extra_args)
        cmd += [str(pcap)]

        started = dt.datetime.now(tz=dt.timezone.utc)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            raise TimeoutError(f"tcpreplay timed out after {timeout_sec}s")

        ended = dt.datetime.now(tz=dt.timezone.utc)
        out = stdout.decode("utf-8", errors="replace") if stdout else ""
        err = stderr.decode("utf-8", errors="replace") if stderr else ""

        log.info("tcpreplay_done", returncode=proc.returncode, cmd=" ".join(shlex.quote(x) for x in cmd))
        return InjectionResult(
            started_at=started, ended_at=ended, returncode=proc.returncode,
            cmd=cmd, stdout=out, stderr=err
        )


# ----------------------------
# Matching and metrics
# ----------------------------

class AlertMatcher:
    def __init__(self, expectations: Sequence[AlertExpectation]) -> None:
        self.expectations = list(expectations)
        self._compiled: Dict[str, re.Pattern] = {e.id: e.compile() for e in self.expectations}

    def match(
        self,
        alerts: Sequence[IDSAlert],
        injection_window: Tuple[dt.datetime, dt.datetime],
    ) -> List[MatchResult]:
        inj_start, inj_end = injection_window
        matches: List[MatchResult] = []

        for exp in self.expectations:
            pat = self._compiled[exp.id]
            since = inj_start - dt.timedelta(seconds=exp.window_before_sec)
            until = inj_end + dt.timedelta(seconds=exp.window_after_sec)

            bucket: List[IDSAlert] = []
            for a in alerts:
                if not _within_window(a.timestamp, since, until):
                    continue

                if exp.min_severity and a.severity is not None and a.severity > exp.min_severity:
                    # В Suricata меньшая цифра = выше приоритет (1=High). Поэтому критерий:
                    # a.severity <= exp.min_severity (если задан). Здесь удерживаем обратную совместимость:
                    pass

                # С учетом шкалы Suricata severity: 1 High, 2 Medium, 3 Low
                if exp.min_severity is not None and a.severity is not None:
                    if a.severity > exp.min_severity:
                        continue

                if exp.src_ip and a.src_ip and exp.src_ip != a.src_ip:
                    continue
                if exp.dst_ip and a.dst_ip and exp.dst_ip != a.dst_ip:
                    continue
                if not pat.search(a.signature or ""):
                    continue
                bucket.append(a)

            count = len(bucket)
            satisfied = (count >= exp.count_min) and (exp.count_max is None or count <= exp.count_max)
            shortfall = 0 if satisfied else max(0, exp.count_min - count)
            matches.append(MatchResult(expectation=exp, matched_alerts=bucket, satisfied=satisfied, shortfall=shortfall))

        return matches

    @staticmethod
    def compute_metrics(matches: Sequence[MatchResult], alerts: Sequence[IDSAlert]) -> Dict[str, Any]:
        tp = sum(1 for m in matches if m.satisfied)
        fn = sum(1 for m in matches if not m.satisfied)
        # FP: алерты, не сопоставленные ни с одним ожиданием по сигнатуре
        all_matched_ids = set(id(a) for m in matches for a in m.matched_alerts)
        fp = sum(1 for a in alerts if id(a) not in all_matched_ids)

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

        return {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "expectations_total": len(matches),
            "alerts_total": len(alerts),
        }


# ----------------------------
# Runner
# ----------------------------

class ControlsValidationRunner:
    def __init__(
        self,
        adapter: IDSAdapter,
        injector: Optional[TrafficInjector],
        expectations: Sequence[AlertExpectation],
        inject_timeout_sec: int = 120,
        post_inject_grace_sec: int = 10,
        read_timeout_sec: int = 30,
        output_dir: Optional[Union[str, Path]] = None,
        write_json: bool = True,
        write_markdown: bool = True,
        write_junit: bool = True,
        fail_on_fn: bool = True,
    ) -> None:
        self.adapter = adapter
        self.injector = injector
        self.expectations = list(expectations)
        self.inject_timeout_sec = inject_timeout_sec
        self.post_inject_grace_sec = post_inject_grace_sec
        self.read_timeout_sec = read_timeout_sec
        self.output_dir = Path(output_dir or "./reports")
        self.write_json = write_json
        self.write_markdown = write_markdown
        self.write_junit = write_junit
        self.fail_on_fn = fail_on_fn

    async def run(
        self,
        pcap: Optional[Union[str, Path]],
        iface: Optional[str],
        inject: bool,
        extra_inject_args: Optional[List[str]] = None,
    ) -> EvaluationReport:
        await self.adapter.health_check()

        inj_start = dt.datetime.now(tz=dt.timezone.utc)
        inj_end = inj_start

        inj_result: Optional[InjectionResult] = None
        if inject:
            if self.injector is None:
                raise IDSCheckError("Injection requested, but injector is not configured")
            if not pcap or not iface:
                raise IDSCheckError("Injection requested, but pcap or iface not provided")

            inj_result = await self.injector.inject_pcap(
                pcap_path=pcap,
                iface=iface,
                timeout_sec=self.inject_timeout_sec,
                extra_args=extra_inject_args
            )
            inj_start = inj_result.started_at
            inj_end = inj_result.ended_at
            if inj_result.returncode != 0:
                log.error("tcpreplay_nonzero_return", returncode=inj_result.returncode)

        # grace period to ensure alerts flushed to EVE
        await asyncio.sleep(max(0, self.post_inject_grace_sec))

        since = inj_start - dt.timedelta(seconds=max(0, self._max_window_before()))
        until = inj_end + dt.timedelta(seconds=max(0, self._max_window_after()))

        # fetch alerts
        alerts = await asyncio.wait_for(self.adapter.fetch_alerts(since=since, until=until),
                                        timeout=self.read_timeout_sec)

        matcher = AlertMatcher(self.expectations)
        match_results = matcher.match(alerts, injection_window=(inj_start, inj_end))
        metrics = matcher.compute_metrics(match_results, alerts)

        report = EvaluationReport(
            started_at=inj_start,
            ended_at=inj_end,
            matches=match_results,
            alerts_seen=alerts,
            metrics=metrics,
            metadata={
                "pcap": str(pcap) if pcap else None,
                "iface": iface,
                "inject": inject,
                "post_inject_grace_sec": self.post_inject_grace_sec,
                "read_timeout_sec": self.read_timeout_sec,
                "tool": "ids_check.py",
                "ids_adapter": type(self.adapter).__name__,
                "injector": type(self.injector).__name__ if self.injector else None,
            }
        )

        self._emit_reports(report)

        # exit condition can be handled by caller; here we just log
        log.info("evaluation_done", metrics=report.metrics)
        return report

    def _max_window_before(self) -> int:
        return max((e.window_before_sec for e in self.expectations), default=0)

    def _max_window_after(self) -> int:
        return max((e.window_after_sec for e in self.expectations), default=0)

    def _emit_reports(self, report: EvaluationReport) -> None:
        _mkdir_p(self.output_dir)
        ts = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        if self.write_json:
            (self.output_dir / f"ids_report_{ts}.json").write_text(
                json.dumps(self._report_to_dict(report), ensure_ascii=False, indent=2),
                encoding="utf-8"
            )

        if self.write_markdown:
            (self.output_dir / f"ids_report_{ts}.md").write_text(
                self._report_to_markdown(report),
                encoding="utf-8"
            )

        if self.write_junit:
            (self.output_dir / f"ids_report_{ts}.xml").write_text(
                self._report_to_junit_xml(report),
                encoding="utf-8"
            )

    @staticmethod
    def _report_to_dict(report: EvaluationReport) -> Dict[str, Any]:
        return {
            "started_at": report.started_at.isoformat(),
            "ended_at": report.ended_at.isoformat(),
            "metrics": report.metrics,
            "matches": [
                {
                    "expectation_id": m.expectation.id,
                    "signature_regex": m.expectation.signature_regex,
                    "min_severity": m.expectation.min_severity,
                    "count_min": m.expectation.count_min,
                    "count_max": m.expectation.count_max,
                    "mitre_techniques": m.expectation.mitre_techniques,
                    "matched_count": len(m.matched_alerts),
                    "satisfied": m.satisfied,
                    "shortfall": m.shortfall,
                    "alerts": [
                        {
                            "timestamp": a.timestamp.isoformat(),
                            "signature": a.signature,
                            "category": a.category,
                            "severity": a.severity,
                            "src_ip": a.src_ip,
                            "src_port": a.src_port,
                            "dst_ip": a.dst_ip,
                            "dst_port": a.dst_port,
                            "proto": a.proto
                        } for a in m.matched_alerts
                    ]
                } for m in report.matches
            ],
            "alerts_seen": [
                {
                    "timestamp": a.timestamp.isoformat(),
                    "signature": a.signature,
                    "category": a.category,
                    "severity": a.severity,
                    "src_ip": a.src_ip,
                    "src_port": a.src_port,
                    "dst_ip": a.dst_ip,
                    "dst_port": a.dst_port,
                    "proto": a.proto
                } for a in report.alerts_seen
            ],
            "metadata": report.metadata
        }

    @staticmethod
    def _report_to_markdown(report: EvaluationReport) -> str:
        lines = []
        lines.append(f"# IDS Controls Validation Report")
        lines.append("")
        lines.append(f"- Started: {report.started_at.isoformat()}")
        lines.append(f"- Ended:   {report.ended_at.isoformat()}")
        lines.append("")
        lines.append("## Metrics")
        for k, v in report.metrics.items():
            lines.append(f"- {k}: {v}")
        lines.append("")
        lines.append("## Expectations")
        for m in report.matches:
            lines.append(f"### {m.expectation.id}")
            lines.append(f"- regex: `{m.expectation.signature_regex}`")
            lines.append(f"- min_severity: {m.expectation.min_severity}")
            lines.append(f"- count_min: {m.expectation.count_min}")
            lines.append(f"- count_max: {m.expectation.count_max}")
            if m.expectation.mitre_techniques:
                lines.append(f"- mitre: {', '.join(m.expectation.mitre_techniques)}")
            lines.append(f"- matched_count: {len(m.matched_alerts)}")
            lines.append(f"- satisfied: {m.satisfied}")
            if not m.satisfied:
                lines.append(f"- shortfall: {m.shortfall}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _report_to_junit_xml(report: EvaluationReport) -> str:
        """
        Генерирует JUnit XML: один testcase на ожидание.
        """
        import xml.etree.ElementTree as ET

        tests = len(report.matches)
        failures = sum(1 for m in report.matches if not m.satisfied)
        suite = ET.Element("testsuite", name="ids_controls_validation",
                           tests=str(tests), failures=str(failures),
                           time=str((report.ended_at - report.started_at).total_seconds()))
        for m in report.matches:
            tc = ET.SubElement(suite, "testcase", classname="ids", name=m.expectation.id)
            if not m.satisfied:
                failure = ET.SubElement(tc, "failure", message="Expectation not satisfied")
                details = {
                    "expected_min": m.expectation.count_min,
                    "found": len(m.matched_alerts),
                    "regex": m.expectation.signature_regex,
                    "min_severity": m.expectation.min_severity
                }
                failure.text = json.dumps(details, ensure_ascii=False)

        return ET.tostring(suite, encoding="unicode")

# ----------------------------
# CLI
# ----------------------------

def _build_adapter(cfg: Dict[str, Any]) -> IDSAdapter:
    t = (cfg.get("ids") or {}).get("type", "suricata_eve").lower()
    if t == "suricata_eve":
        eve = (cfg.get("ids") or {}).get("eve_file")
        if not eve:
            raise IDSCheckError("ids.eve_file must be provided for suricata_eve")
        return SuricataEveAdapter(eve_file=eve)
    raise IDSCheckError(f"Unsupported ids.type: {t}")


def _build_injector(cfg: Dict[str, Any]) -> Optional[TrafficInjector]:
    scenario = cfg.get("scenario") or {}
    inject = bool(scenario.get("inject", False))
    if not inject:
        return None
    exe = scenario.get("tcpreplay") or "tcpreplay"
    return TrafficInjector(executable=exe)


def _parse_expectations(cfg: Dict[str, Any]) -> List[AlertExpectation]:
    items = cfg.get("expectations") or []
    out: List[AlertExpectation] = []
    for item in items:
        out.append(AlertExpectation(
            id=item["id"],
            signature_regex=item["signature_regex"],
            min_severity=int(item.get("min_severity", 1)),
            src_ip=item.get("src_ip"),
            dst_ip=item.get("dst_ip"),
            count_min=int(item.get("count_min", 1)),
            count_max=(int(item["count_max"]) if item.get("count_max") is not None else None),
            mitre_techniques=list(item.get("mitre_techniques") or []),
            window_before_sec=int(item.get("window_before_sec", 0)),
            window_after_sec=int(item.get("window_after_sec", 60)),
        ))
    return out


async def _main_async(args: argparse.Namespace) -> int:
    _setup_logging(os.getenv("LOG_LEVEL", "INFO"))

    cfg = _load_config(Path(args.config))
    adapter = _build_adapter(cfg)
    injector = _build_injector(cfg)
    expectations = _parse_expectations(cfg)

    timings = cfg.get("timings") or {}
    inject_timeout = int(timings.get("inject_timeout_sec", 120))
    post_inject_grace = int(timings.get("post_inject_grace_sec", 10))
    read_timeout = int(timings.get("read_timeout_sec", 30))

    reporting = cfg.get("reporting") or {}
    output_dir = reporting.get("output_dir") or "./reports"
    write_json = bool(reporting.get("write_json", True))
    write_md = bool(reporting.get("write_markdown", True))
    write_junit = bool(reporting.get("write_junit", True))
    fail_on_fn = bool(reporting.get("fail_on_fn", True))

    scenario = cfg.get("scenario") or {}
    pcap = scenario.get("pcap")
    iface = scenario.get("iface")
    inject = bool(scenario.get("inject", False))
    extra_inject_args = scenario.get("extra_args") or None

    runner = ControlsValidationRunner(
        adapter=adapter,
        injector=injector,
        expectations=expectations,
        inject_timeout_sec=inject_timeout,
        post_inject_grace_sec=post_inject_grace,
        read_timeout_sec=read_timeout,
        output_dir=output_dir,
        write_json=write_json,
        write_markdown=write_md,
        write_junit=write_junit,
        fail_on_fn=fail_on_fn,
    )

    try:
        report = await runner.run(
            pcap=pcap,
            iface=iface,
            inject=inject,
            extra_inject_args=extra_inject_args
        )
    except TimeoutError as e:
        log.error("timeout", error=str(e))
        return 124
    except IDSCheckError as e:
        log.error("ids_check_error", error=str(e))
        return 2
    except Exception as e:
        log.exception("unexpected_error")
        return 1

    # Определяем код возврата: если есть FN и флаг активен — ошибка
    exit_code = 0
    if runner.fail_on_fn and report.metrics.get("false_negative", 0) > 0:
        exit_code = 3

    return exit_code


def main() -> None:
    parser = argparse.ArgumentParser(description="IDS Controls Validation Harness")
    parser.add_argument("--config", required=True, help="Path to JSON/YAML config")
    args = parser.parse_args()
    code = asyncio.run(_main_async(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
