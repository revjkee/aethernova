# SPDX-License-Identifier: Apache-2.0
# automation-core/src/automation_core/pipelines/news_to_excel.py
"""
Пайплайн агрегации новостей в Excel/CSV.

Формат спецификации источников (YAML или JSON):
  - name: "Example RSS"
    url: "https://example.org/feed.xml"
    kind: "rss"
    limit: 50
  - name: "Example HTML"
    url: "https://example.org/news"
    kind: "html"
    html:
      item_selector: "article.post"
      title_selector: "h2 a"
      link_selector: "h2 a[href]"
      date_selector: "time[datetime]"
      date_attr: "datetime"
      summary_selector: ".excerpt"

Запуск:
  poetry run python -m automation_core.pipelines.news_to_excel \
    --sources ./sources.yaml \
    --out ./news.xlsx \
    --per-source-limit 50 \
    --concurrency 16

Зависимости используются опционально:
  - feedparser (для RSS, иначе fallback на минимальный парсинг)
  - beautifulsoup4 + lxml (для HTML)
  - pandas + openpyxl (Excel; при отсутствии openpyxl — CSV)
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import dataclasses
import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

try:
    import feedparser  # type: ignore
except Exception:  # pragma: no cover
    feedparser = None  # type: ignore

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore

try:
    import pandas as pd  # type: ignore
except Exception:  # pragma: no cover
    pd = None  # type: ignore

from automation_core.config.settings import settings
from automation_core.http_client.httpx_async import AsyncHTTPClient, default_http_client

# robots-комплаенс опционален
try:
    from automation_core.compliance.robots import is_allowed  # type: ignore
except Exception:  # pragma: no cover
    def is_allowed(url: str, user_agent: str) -> bool:
        return True

# опциональные метрики
try:
    from automation_core.observability.metrics import record_counter, record_histogram  # type: ignore
except Exception:  # pragma: no cover
    def record_counter(*args: Any, **kwargs: Any) -> None: ...
    def record_histogram(*args: Any, **kwargs: Any) -> None: ...

# опциональный OpenTelemetry
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer("automation-core.pipelines.news-to-excel")
except Exception:  # pragma: no cover
    _tracer = None  # type: ignore

log = logging.getLogger(__name__)


# ---------------------------
# Модели
# ---------------------------

@dataclass(frozen=True)
class HTMLSpec:
    item_selector: str
    title_selector: str
    link_selector: str
    date_selector: Optional[str] = None
    date_attr: Optional[str] = None
    summary_selector: Optional[str] = None


@dataclass(frozen=True)
class SourceSpec:
    name: str
    url: str
    kind: str  # "rss" | "html"
    html: Optional[HTMLSpec] = None
    limit: Optional[int] = None


@dataclass(frozen=True)
class Article:
    source: str
    title: str
    url: str
    published_at: Optional[datetime]  # UTC
    summary: Optional[str]
    language: Optional[str]
    fetched_at: datetime  # UTC


# ---------------------------
# Вспомогательные функции
# ---------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_date(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    # 1) email.utils
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass
    # 2) dateutil (если установлен)
    try:
        from dateutil import parser as date_parser  # type: ignore
        dt = date_parser.parse(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _deduplicate(articles: list[Article]) -> list[Article]:
    seen: set[str] = set()
    result: list[Article] = []
    for a in articles:
        key = a.url.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(a)
    return result


def _load_sources(path: Path) -> list[SourceSpec]:
    if not path.exists():
        raise FileNotFoundError(f"Sources file not found: {path}")
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is not installed, cannot parse YAML sources.")
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Sources spec must be a list.")
    specs: list[SourceSpec] = []
    for item in raw:
        kind = str(item.get("kind", "rss")).lower()
        html_spec = None
        if kind == "html":
            html = item.get("html") or {}
            html_spec = HTMLSpec(
                item_selector=html["item_selector"],
                title_selector=html["title_selector"],
                link_selector=html["link_selector"],
                date_selector=html.get("date_selector"),
                date_attr=html.get("date_attr"),
                summary_selector=html.get("summary_selector"),
            )
        specs.append(
            SourceSpec(
                name=item["name"],
                url=item["url"],
                kind=kind,
                html=html_spec,
                limit=item.get("limit"),
            )
        )
    return specs


# ---------------------------
# Парсеры источников
# ---------------------------

def _parse_rss_bytes(data: bytes, src: SourceSpec) -> list[Article]:
    fetched_at = _now_utc()
    results: list[Article] = []
    if feedparser is None:
        log.warning("feedparser is not installed; RSS parsing will be limited.")
        return results
    fp = feedparser.parse(data)  # type: ignore
    entries = fp.entries or []
    for e in entries:
        title = (getattr(e, "title", "") or "").strip()
        link = (getattr(e, "link", "") or "").strip()
        # published_parsed может отсутствовать; используем полезные поля по ситуации
        pub = None
        if getattr(e, "published", None):
            pub = _parse_date(str(e.published))
        elif getattr(e, "updated", None):
            pub = _parse_date(str(e.updated))
        summary = (getattr(e, "summary", "") or "").strip() or None
        lang = (getattr(fp.feed, "language", "") or "").strip() or None
        if title and link:
            results.append(
                Article(
                    source=src.name,
                    title=title,
                    url=link,
                    published_at=pub,
                    summary=summary,
                    language=lang,
                    fetched_at=fetched_at,
                )
            )
    return results


def _parse_html_bytes(data: bytes, src: SourceSpec) -> list[Article]:
    if BeautifulSoup is None:
        log.warning("beautifulsoup4 is not installed; HTML parsing is unavailable.")
        return []
    assert src.html is not None
    fetched_at = _now_utc()
    soup = BeautifulSoup(data, "lxml")
    items = soup.select(src.html.item_selector)
    results: list[Article] = []
    for el in items:
        t_el = el.select_one(src.html.title_selector)
        l_el = el.select_one(src.html.link_selector)
        if not t_el or not l_el:
            continue
        title = t_el.get_text(strip=True)
        link = l_el.get("href") or l_el.get("src") or ""
        link = link.strip()
        # Дата при наличии
        pub: Optional[datetime] = None
        if src.html.date_selector:
            d_el = el.select_one(src.html.date_selector)
            if d_el:
                if src.html.date_attr:
                    pub = _parse_date(d_el.get(src.html.date_attr))
                else:
                    pub = _parse_date(d_el.get_text(strip=True))
        summary = None
        if src.html.summary_selector:
            s_el = el.select_one(src.html.summary_selector)
            if s_el:
                summary = s_el.get_text(strip=True) or None
        if title and link:
            results.append(
                Article(
                    source=src.name,
                    title=title,
                    url=link,
                    published_at=pub,
                    summary=summary,
                    language=None,
                    fetched_at=fetched_at,
                )
            )
    return results


# ---------------------------
# Загрузка и обработка
# ---------------------------

async def _fetch_bytes(cli: AsyncHTTPClient, url: str) -> Optional[bytes]:
    if not is_allowed(url, settings.http.user_agent):
        log.info("robots.txt disallows fetching: %s", url)
        return None
    try:
        resp = await cli.get(url)
        resp.raise_for_status()
        record_counter("news_fetch_ok_total", 1, attributes={"host": resp.request.url.host})
        return await resp.aread()
    except Exception as e:
        log.warning("fetch failed: %s (%s)", url, e.__class__.__name__)
        record_counter("news_fetch_fail_total", 1, attributes={"reason": e.__class__.__name__})
        return None


async def _collect_from_source(cli: AsyncHTTPClient, src: SourceSpec, per_source_limit: int) -> list[Article]:
    limit = min(per_source_limit, src.limit or per_source_limit)
    data = await _fetch_bytes(cli, src.url)
    if not data:
        return []
    if _tracer:
        span_cm = _tracer.start_as_current_span("parse_source", attributes={"source": src.name, "kind": src.kind})
    else:
        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def span_cm():  # type: ignore
            yield
    async with span_cm:
        if src.kind == "rss":
            items = _parse_rss_bytes(data, src)
        elif src.kind == "html":
            if not src.html:
                log.warning("HTML spec missing for source: %s", src.name)
                return []
            items = _parse_html_bytes(data, src)
        else:
            log.warning("Unknown source kind: %s", src.kind)
            return []
    # обрезаем
    if limit and len(items) > limit:
        items = items[:limit]
    return items


async def gather_news(
    sources: list[SourceSpec],
    *,
    concurrency: int,
    per_source_limit: int,
) -> list[Article]:
    sem = asyncio.Semaphore(concurrency)
    results: list[Article] = []

    async with default_http_client() as cli:
        async def run_one(src: SourceSpec) -> None:
            async with sem:
                items = await _collect_from_source(cli, src, per_source_limit)
                results.extend(items)

        tasks = [asyncio.create_task(run_one(s)) for s in sources]
        await asyncio.gather(*tasks)

    results = _deduplicate(results)
    record_histogram("news_articles_collected", len(results), attributes={"sources": len(sources)})
    return results


# ---------------------------
# Экспорт
# ---------------------------

def _articles_to_rows(arts: Iterable[Article]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for a in arts:
        rows.append(
            {
                "source": a.source,
                "title": a.title,
                "url": a.url,
                "published_at": a.published_at.isoformat() if a.published_at else None,
                "summary": a.summary,
                "language": a.language,
                "fetched_at": a.fetched_at.isoformat(),
            }
        )
    return rows


def save_excel_or_csv(rows: list[dict[str, Any]], out_path: Path) -> Path:
    _ensure_parent_dir(out_path)
    # Стараемся Excel, при отсутствии зависимостей — CSV
    if pd is not None and out_path.suffix.lower() in (".xlsx", ".xlsm", ".xltx", ".xltm"):
        try:
            df = pd.DataFrame(rows)
            # engine выбирается автоматически; если openpyxl недоступен — будет ошибка
            df.to_excel(out_path, index=False)
            return out_path
        except Exception:
            # Фоллбек в CSV рядом
            csv_path = out_path.with_suffix(".csv")
            log.warning("Excel export failed; falling back to CSV: %s", csv_path)
            return save_csv(rows, csv_path)
    # Прямой CSV
    return save_csv(rows, out_path if out_path.suffix.lower() == ".csv" else out_path.with_suffix(".csv"))


def save_csv(rows: list[dict[str, Any]], out_path: Path) -> Path:
    _ensure_parent_dir(out_path)
    if not rows:
        # создаём пустой CSV с заголовком
        header = ["source", "title", "url", "published_at", "summary", "language", "fetched_at"]
        with out_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)
        return out_path

    header = list(rows[0].keys())
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)
    return out_path


# ---------------------------
# CLI
# ---------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Aggregate news from sources and export to Excel/CSV.")
    p.add_argument("--sources", type=Path, required=True, help="Path to YAML/JSON with sources spec.")
    p.add_argument("--out", type=Path, required=True, help="Output file (.xlsx or .csv).")
    p.add_argument("--per-source-limit", type=int, default=50, help="Max items per source.")
    p.add_argument(
        "--concurrency",
        type=int,
        default=max(1, min(settings.concurrency.max_concurrency, 64)),
        help="Parallelism level.",
    )
    return p.parse_args(argv)


async def _main_async(ns: argparse.Namespace) -> int:
    # Базовое логирование, если не настроено извне
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=getattr(logging, settings.observability.log_level, logging.INFO),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

    try:
        sources = _load_sources(ns.sources)
    except Exception as e:
        log.error("Failed to load sources: %s", e)
        return 2

    articles = await gather_news(
        sources,
        concurrency=max(1, ns.concurrency),
        per_source_limit=max(1, ns.per_source_limit),
    )
    rows = _articles_to_rows(articles)
    out = save_excel_or_csv(rows, ns.out)
    log.info("Saved %d articles to %s", len(rows), out)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ns = parse_args(argv or sys.argv[1:])
    return asyncio.run(_main_async(ns))


if __name__ == "__main__":
    raise SystemExit(main())
