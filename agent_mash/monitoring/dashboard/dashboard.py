# agent_mash/monitoring/dashboard/dashboard.py

from __future__ import annotations

import dataclasses
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import tempfile
import typing as t
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

__all__ = [
    "DashboardError",
    "DashboardValidationError",
    "DashboardIOError",
    "DashboardKind",
    "TimeRange",
    "DatasourceKind",
    "DatasourceRef",
    "Threshold",
    "SeriesSpec",
    "WidgetKind",
    "Widget",
    "Layout",
    "DashboardMeta",
    "Dashboard",
    "DashboardBuilder",
    "Redactor",
    "DefaultRedactor",
    "Renderer",
    "JsonRenderer",
    "FilePublisher",
]


class DashboardError(RuntimeError):
    pass


class DashboardValidationError(DashboardError, ValueError):
    pass


class DashboardIOError(DashboardError, OSError):
    pass


class DashboardKind(str, Enum):
    ops = "ops"
    security = "security"
    product = "product"
    finance = "finance"
    ai = "ai"
    other = "other"


class WidgetKind(str, Enum):
    timeseries = "timeseries"
    stat = "stat"
    table = "table"
    logs = "logs"
    text = "text"
    heatmap = "heatmap"
    gauge = "gauge"
    alert_list = "alert_list"


class DatasourceKind(str, Enum):
    prometheus = "prometheus"
    loki = "loki"
    otel = "otel"
    elastic = "elastic"
    sql = "sql"
    http = "http"
    custom = "custom"


def _utc_now() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


def _require_str(name: str, value: str, *, max_len: int | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DashboardValidationError(f"{name} must be a non-empty string")
    v = value.strip()
    if max_len is not None and len(v) > max_len:
        raise DashboardValidationError(f"{name} length must be <= {max_len}")
    return v


def _require_int(name: str, value: int, *, min_v: int | None = None, max_v: int | None = None) -> int:
    if not isinstance(value, int):
        raise DashboardValidationError(f"{name} must be int")
    if min_v is not None and value < min_v:
        raise DashboardValidationError(f"{name} must be >= {min_v}")
    if max_v is not None and value > max_v:
        raise DashboardValidationError(f"{name} must be <= {max_v}")
    return value


def _require_bool(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise DashboardValidationError(f"{name} must be bool")
    return value


def _as_utc(ts: dt.datetime) -> dt.datetime:
    if not isinstance(ts, dt.datetime):
        raise DashboardValidationError("timestamp must be datetime")
    if ts.tzinfo is None:
        raise DashboardValidationError("timestamp must be timezone-aware")
    return ts.astimezone(dt.timezone.utc)


def _stable_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _json_dumps(obj: t.Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True, slots=True)
class TimeRange:
    """
    Time range definition.
    mode:
      - "relative": uses from_expr like "now-6h"
      - "absolute": uses from_ts/to_ts as ISO8601
    """
    mode: str  # relative|absolute
    from_expr: str = "now-6h"
    to_expr: str = "now"
    from_ts: str = ""
    to_ts: str = ""

    def validate(self) -> "TimeRange":
        mode = _require_str("time_range.mode", self.mode, max_len=32)
        if mode not in ("relative", "absolute"):
            raise DashboardValidationError("time_range.mode must be 'relative' or 'absolute'")
        if mode == "relative":
            _require_str("time_range.from_expr", self.from_expr, max_len=64)
            _require_str("time_range.to_expr", self.to_expr, max_len=64)
        else:
            _require_str("time_range.from_ts", self.from_ts, max_len=64)
            _require_str("time_range.to_ts", self.to_ts, max_len=64)
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class DatasourceRef:
    """
    Datasource reference (abstract): can map to real provider config elsewhere.
    """
    name: str
    kind: DatasourceKind
    uid: str = ""
    namespace: str = "default"
    config: dict[str, t.Any] = field(default_factory=dict)

    def validate(self) -> "DatasourceRef":
        _require_str("datasource.name", self.name, max_len=80)
        if not isinstance(self.kind, DatasourceKind):
            raise DashboardValidationError("datasource.kind must be DatasourceKind")
        if self.uid:
            _require_str("datasource.uid", self.uid, max_len=120)
        _require_str("datasource.namespace", self.namespace, max_len=80)
        if not isinstance(self.config, dict):
            raise DashboardValidationError("datasource.config must be dict")
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "name": self.name,
            "kind": self.kind.value,
            "uid": self.uid,
            "namespace": self.namespace,
            "config": self.config,
        }


@dataclass(frozen=True, slots=True)
class Threshold:
    """
    Generic threshold model for alerting-like visualization.
    """
    label: str
    op: str  # > >= < <= == !=
    value: float

    def validate(self) -> "Threshold":
        _require_str("threshold.label", self.label, max_len=80)
        _require_str("threshold.op", self.op, max_len=8)
        if self.op not in (">", ">=", "<", "<=", "==", "!="):
            raise DashboardValidationError("threshold.op invalid")
        if not isinstance(self.value, (int, float)):
            raise DashboardValidationError("threshold.value must be number")
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {"label": self.label, "op": self.op, "value": float(self.value)}


@dataclass(frozen=True, slots=True)
class SeriesSpec:
    """
    Widget series definition.
    query: provider-specific query (PromQL/LogQL/SQL/etc.)
    legend: label template
    """
    name: str
    query: str
    legend: str = ""
    unit: str = ""
    thresholds: tuple[Threshold, ...] = ()

    def validate(self) -> "SeriesSpec":
        _require_str("series.name", self.name, max_len=120)
        _require_str("series.query", self.query, max_len=20_000)
        if self.legend:
            _require_str("series.legend", self.legend, max_len=400)
        if self.unit:
            _require_str("series.unit", self.unit, max_len=32)
        if not isinstance(self.thresholds, tuple):
            raise DashboardValidationError("series.thresholds must be tuple")
        for th in self.thresholds:
            if not isinstance(th, Threshold):
                raise DashboardValidationError("series.thresholds must contain Threshold")
            th.validate()
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "name": self.name,
            "query": self.query,
            "legend": self.legend,
            "unit": self.unit,
            "thresholds": [x.to_dict() for x in self.thresholds],
        }


@dataclass(frozen=True, slots=True)
class Layout:
    """
    Simple grid layout. Coordinates in grid units.
    """
    x: int
    y: int
    w: int
    h: int

    def validate(self) -> "Layout":
        _require_int("layout.x", self.x, min_v=0, max_v=10_000)
        _require_int("layout.y", self.y, min_v=0, max_v=10_000)
        _require_int("layout.w", self.w, min_v=1, max_v=10_000)
        _require_int("layout.h", self.h, min_v=1, max_v=10_000)
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {"x": self.x, "y": self.y, "w": self.w, "h": self.h}


@dataclass(frozen=True, slots=True)
class Widget:
    """
    A dashboard widget (panel).
    """
    title: str
    kind: WidgetKind
    datasource: str  # name of DatasourceRef
    layout: Layout
    series: tuple[SeriesSpec, ...] = ()
    options: dict[str, t.Any] = field(default_factory=dict)
    description: str = ""
    widget_id: str = field(init=False)

    def __post_init__(self) -> None:
        payload = _json_dumps(
            {
                "title": self.title,
                "kind": self.kind.value if isinstance(self.kind, WidgetKind) else str(self.kind),
                "datasource": self.datasource,
                "layout": self.layout.to_dict() if isinstance(self.layout, Layout) else {},
                "series": [s.to_dict() for s in self.series] if isinstance(self.series, tuple) else [],
                "options": self.options,
            }
        )
        object.__setattr__(self, "widget_id", _stable_hash(payload))

    def validate(self) -> "Widget":
        _require_str("widget.title", self.title, max_len=200)
        if not isinstance(self.kind, WidgetKind):
            raise DashboardValidationError("widget.kind must be WidgetKind")
        _require_str("widget.datasource", self.datasource, max_len=80)
        if not isinstance(self.layout, Layout):
            raise DashboardValidationError("widget.layout must be Layout")
        self.layout.validate()
        if not isinstance(self.series, tuple):
            raise DashboardValidationError("widget.series must be tuple")
        for s in self.series:
            if not isinstance(s, SeriesSpec):
                raise DashboardValidationError("widget.series must contain SeriesSpec")
            s.validate()
        if not isinstance(self.options, dict):
            raise DashboardValidationError("widget.options must be dict")
        if self.description:
            _require_str("widget.description", self.description, max_len=10_000)
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "widget_id": self.widget_id,
            "title": self.title,
            "kind": self.kind.value,
            "datasource": self.datasource,
            "layout": self.layout.to_dict(),
            "series": [s.to_dict() for s in self.series],
            "options": self.options,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class DashboardMeta:
    schema_version: str = "1.0"
    kind: DashboardKind = DashboardKind.other
    title: str = "Dashboard"
    created_at: dt.datetime = field(default_factory=_utc_now)
    dashboard_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    tags: tuple[str, ...] = ()
    owner: str = ""
    description: str = ""
    context: dict[str, t.Any] = field(default_factory=dict)

    def validate(self) -> "DashboardMeta":
        _require_str("meta.schema_version", self.schema_version, max_len=32)
        if not isinstance(self.kind, DashboardKind):
            raise DashboardValidationError("meta.kind must be DashboardKind")
        _require_str("meta.title", self.title, max_len=160)
        _as_utc(self.created_at)
        _require_str("meta.dashboard_id", self.dashboard_id, max_len=64)
        _require_str("meta.trace_id", self.trace_id, max_len=64)
        if not isinstance(self.tags, tuple):
            raise DashboardValidationError("meta.tags must be tuple")
        if self.owner:
            _require_str("meta.owner", self.owner, max_len=120)
        if self.description:
            _require_str("meta.description", self.description, max_len=20_000)
        if not isinstance(self.context, dict):
            raise DashboardValidationError("meta.context must be dict")
        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind.value,
            "title": self.title,
            "created_at": self.created_at.isoformat(),
            "dashboard_id": self.dashboard_id,
            "trace_id": self.trace_id,
            "tags": list(self.tags),
            "owner": self.owner,
            "description": self.description,
            "context": self.context,
        }


@dataclass(frozen=True, slots=True)
class Dashboard:
    meta: DashboardMeta
    time_range: TimeRange = field(default_factory=TimeRange)
    datasources: tuple[DatasourceRef, ...] = ()
    widgets: tuple[Widget, ...] = ()
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        payload = _json_dumps(
            {
                "meta": self.meta.to_dict(),
                "time_range": self.time_range.to_dict(),
                "datasources": [d.to_dict() for d in self.datasources],
                "widgets": [w.to_dict() for w in self.widgets],
            }
        )
        object.__setattr__(self, "fingerprint", _stable_hash(payload))

    def validate(self) -> "Dashboard":
        if not isinstance(self.meta, DashboardMeta):
            raise DashboardValidationError("dashboard.meta must be DashboardMeta")
        self.meta.validate()

        if not isinstance(self.time_range, TimeRange):
            raise DashboardValidationError("dashboard.time_range must be TimeRange")
        self.time_range.validate()

        if not isinstance(self.datasources, tuple):
            raise DashboardValidationError("dashboard.datasources must be tuple")
        ds_names: set[str] = set()
        for d in self.datasources:
            if not isinstance(d, DatasourceRef):
                raise DashboardValidationError("dashboard.datasources must contain DatasourceRef")
            d.validate()
            if d.name in ds_names:
                raise DashboardValidationError(f"duplicate datasource name: {d.name}")
            ds_names.add(d.name)

        if not isinstance(self.widgets, tuple):
            raise DashboardValidationError("dashboard.widgets must be tuple")
        used_layouts: set[tuple[int, int, int, int]] = set()
        for w in self.widgets:
            if not isinstance(w, Widget):
                raise DashboardValidationError("dashboard.widgets must contain Widget")
            w.validate()
            if w.datasource not in ds_names:
                raise DashboardValidationError(f"widget datasource not declared: {w.datasource}")
            key = (w.layout.x, w.layout.y, w.layout.w, w.layout.h)
            if key in used_layouts:
                raise DashboardValidationError("widgets share identical layout slot")
            used_layouts.add(key)

        return self

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "meta": self.meta.to_dict(),
            "fingerprint": self.fingerprint,
            "time_range": self.time_range.to_dict(),
            "datasources": [d.to_dict() for d in self.datasources],
            "widgets": [w.to_dict() for w in self.widgets],
        }


class Redactor(t.Protocol):
    def redact(self, obj: t.Any) -> t.Any:
        ...


class DefaultRedactor:
    _SENSITIVE_KEY_RE = re.compile(
        r"(?i)^(.*_)?(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|cookie|session)(_.+)?$"
    )
    _INLINE_RE = re.compile(
        r"(?i)\b("
        r"sk-[a-z0-9]{16,}"
        r"|ghp_[a-z0-9]{20,}"
        r"|xox[baprs]-[a-z0-9-]{10,}"
        r"|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"
        r")\b"
    )

    def __init__(self, redaction: str = "[REDACTED]") -> None:
        self._redaction = redaction

    def redact(self, obj: t.Any) -> t.Any:
        return self._walk(obj)

    def _walk(self, obj: t.Any) -> t.Any:
        if obj is None:
            return None
        if isinstance(obj, (bool, int, float)):
            return obj
        if isinstance(obj, str):
            return self._INLINE_RE.sub(self._redaction, obj)
        if isinstance(obj, list):
            return [self._walk(x) for x in obj]
        if isinstance(obj, tuple):
            return tuple(self._walk(x) for x in obj)
        if isinstance(obj, dict):
            out: dict[t.Any, t.Any] = {}
            for k, v in obj.items():
                ks = str(k).strip()
                if self._SENSITIVE_KEY_RE.match(ks):
                    out[k] = self._redaction
                else:
                    out[k] = self._walk(v)
            return out
        if dataclasses.is_dataclass(obj):
            return self._walk(dataclasses.asdict(obj))
        return obj


class Renderer(t.Protocol):
    content_type: str
    file_ext: str

    def render(self, dashboard: Dashboard, *, redactor: Redactor | None = None) -> str:
        ...


class JsonRenderer:
    content_type = "application/json; charset=utf-8"
    file_ext = ".json"

    def render(self, dashboard: Dashboard, *, redactor: Redactor | None = None) -> str:
        dashboard.validate()
        payload = dashboard.to_dict()
        if redactor is not None:
            payload = t.cast(dict[str, t.Any], redactor.redact(payload))
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


class FilePublisher:
    """
    Publishes dashboard artifacts to filesystem with atomic writes.

    Output filename defaults:
      {kind}_{YYYYMMDDTHHMMSSZ}_{dashboard_id}_{fingerprint}.json[.gz]
    """

    _SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")

    def __init__(self, base_dir: str | os.PathLike[str]) -> None:
        self.base_dir = Path(base_dir)

    def publish(
        self,
        dashboard: Dashboard,
        *,
        renderer: Renderer | None = None,
        redactor: Redactor | None = None,
        compress_gzip: bool = False,
        filename_hint: str | None = None,
    ) -> Path:
        renderer = renderer or JsonRenderer()
        dashboard.validate()

        self.base_dir.mkdir(parents=True, exist_ok=True)

        meta = dashboard.meta
        ts = meta.created_at.strftime("%Y%m%dT%H%M%SZ")
        kind = meta.kind.value
        stem = self._safe_name(filename_hint) if filename_hint else f"{kind}_{ts}_{meta.dashboard_id}_{dashboard.fingerprint}"
        ext = renderer.file_ext + (".gz" if compress_gzip else "")
        out_path = (self.base_dir / (stem + ext)).resolve()

        try:
            content = renderer.render(dashboard, redactor=redactor)
            self._atomic_write(out_path, content.encode("utf-8"), gzip_compress=compress_gzip)
            return out_path
        except Exception as e:
            raise DashboardIOError(f"failed to publish dashboard to {out_path}: {e}") from e

    @classmethod
    def _safe_name(cls, name: str) -> str:
        name = name.strip()
        name = cls._SAFE_NAME_RE.sub("_", name)
        name = name.strip("._-")
        return name[:180] if name else "dashboard"

    @staticmethod
    def _atomic_write(path: Path, data: bytes, *, gzip_compress: bool) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd: int | None = None
        tmp_path: str | None = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
            with os.fdopen(fd, "wb") as f:
                if gzip_compress:
                    with gzip.GzipFile(filename=path.name, mode="wb", fileobj=f, compresslevel=6) as gz:
                        gz.write(data)
                else:
                    f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(path))
        finally:
            if tmp_path is not None:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except OSError:
                    pass


class DashboardBuilder:
    """
    Ergonomic, validated dashboard builder.
    """

    def __init__(
        self,
        *,
        kind: DashboardKind,
        title: str,
        schema_version: str = "1.0",
        tags: t.Iterable[str] = (),
        owner: str = "",
        description: str = "",
        context: dict[str, t.Any] | None = None,
        created_at: dt.datetime | None = None,
        dashboard_id: str | None = None,
        trace_id: str | None = None,
        time_range: TimeRange | None = None,
    ) -> None:
        meta = DashboardMeta(
            schema_version=schema_version,
            kind=kind,
            title=title,
            created_at=_as_utc(created_at) if created_at is not None else _utc_now(),
            dashboard_id=dashboard_id or uuid.uuid4().hex,
            trace_id=trace_id or uuid.uuid4().hex,
            tags=tuple(str(x) for x in tags),
            owner=owner,
            description=description,
            context=dict(context or {}),
        ).validate()

        self._meta = meta
        self._time_range = (time_range or TimeRange(mode="relative")).validate()
        self._datasources: dict[str, DatasourceRef] = {}
        self._widgets: list[Widget] = []

    def datasource(
        self,
        *,
        name: str,
        kind: DatasourceKind,
        uid: str = "",
        namespace: str = "default",
        config: dict[str, t.Any] | None = None,
    ) -> "DashboardBuilder":
        ds = DatasourceRef(
            name=name,
            kind=kind,
            uid=uid,
            namespace=namespace,
            config=dict(config or {}),
        ).validate()
        if ds.name in self._datasources:
            raise DashboardValidationError(f"duplicate datasource name: {ds.name}")
        self._datasources[ds.name] = ds
        return self

    def widget(
        self,
        *,
        title: str,
        kind: WidgetKind,
        datasource: str,
        layout: Layout,
        series: t.Iterable[SeriesSpec] = (),
        options: dict[str, t.Any] | None = None,
        description: str = "",
    ) -> "DashboardBuilder":
        w = Widget(
            title=title,
            kind=kind,
            datasource=datasource,
            layout=layout,
            series=tuple(series),
            options=dict(options or {}),
            description=description,
        ).validate()
        self._widgets.append(w)
        return self

    def build(self) -> Dashboard:
        dash = Dashboard(
            meta=self._meta,
            time_range=self._time_range,
            datasources=tuple(self._datasources.values()),
            widgets=tuple(self._widgets),
        ).validate()
        return dash
