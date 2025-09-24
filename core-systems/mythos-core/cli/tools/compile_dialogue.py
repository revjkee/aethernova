#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mythos Core — Dialogue Compiler CLI

Назначение:
  - Свести диалог/таймлайн к нормализованной форме сообщений
  - Отсортировать и дедуплицировать
  - Опционально маскировать PII
  - Экспорт: md | json | jsonl | chatml (messages)
  - Разбиение на сессии по временному зазору

Зависимости:
  - Обязательных нет (используется только стандартная библиотека)
  - Опционально: PyYAML для YAML (если установлен)
  - Опционально: mythos.moderation.filters для качественного PII-маскирования

Коды выхода:
  0 — успех
  1 — ошибки валидации/входных данных
  2 — ошибки ввода/вывода
  3 — прочие исключения
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------- optional imports ----------
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

# PII support via mythos.moderation.filters (if available)
try:
    from mythos.moderation.filters import PIIFilter, mask_pii  # type: ignore
except Exception:  # pragma: no cover
    PIIFilter = None  # type: ignore
    def mask_pii(text: str, spans: List[Tuple[int, int]], mask_char: str = "•") -> str:
        # simple fallback mask (same signature)
        if not text or not spans:
            return text
        spans = sorted(spans, key=lambda x: x[0])
        merged: List[Tuple[int, int]] = []
        for s, e in spans:
            if not merged or s > merged[-1][1]:
                merged.append((s, e))
            else:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        out, last = [], 0
        for s, e in merged:
            out.append(text[last:s])
            out.append(mask_char * max(0, e - s))
            last = e
        out.append(text[last:])
        return "".join(out)

# Fallback PII regex (при отсутствии PIIFilter)
EMAIL_RE = re.compile(r"(?i)(?:[a-z0-9._%+\-]+)@(?:[a-z0-9\-]+\.)+[a-z]{2,}")
PHONE_RE = re.compile(r"(?:(?:\+?\d[\s\-()]*){7,}\d)")
CARD_RE  = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

ISO8601_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


# ---------- internal model ----------

@dataclass
class Msg:
    dialogue_id: str
    turn_id: Optional[str]
    ts: dt.datetime
    role: str            # system|user|assistant|tool|unknown
    actor_id: Optional[str]
    actor_name: Optional[str]
    text: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class CompileResult:
    dialogue_id: str
    title: Optional[str]
    created_at: Optional[dt.datetime]
    updated_at: Optional[dt.datetime]
    participants: Dict[str, str]  # actor_id -> display_name
    messages: List[Msg]
    usage_total: Dict[str, int]


# ---------- helpers ----------

def _parse_ts(s: str) -> dt.datetime:
    # приемлемы ISO 8601 c/без Z, с миллисекундами
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except Exception:
        # last resort
        return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z").astimezone(dt.timezone.utc)

def _safe_get(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def _role_from_actor_enum(actor: Optional[str]) -> str:
    mapping = {
        "ACTOR_SYSTEM": "system",
        "ACTOR_USER": "user",
        "ACTOR_ASSISTANT": "assistant",
        "ACTOR_TOOL": "tool",
    }
    return mapping.get(actor or "", "unknown")

def _role_from_event_actorname(name: Optional[str]) -> str:
    if not name:
        return "unknown"
    low = name.lower()
    if "assistant" in low or "bot" in low:
        return "assistant"
    if "system" in low:
        return "system"
    return "user"

def _detect_pii_spans(text: str) -> List[Tuple[int, int]]:
    if not text:
        return []
    if PIIFilter:
        # используем точные шаблоны из модуля модерации
        ctx = {"plain_text": text}
        spans: List[Tuple[int, int]] = []
        reasons = PIIFilter().apply(inp=None, cfg=None, ctx=ctx)  # type: ignore[arg-type]
        for r in reasons:
            if r.span:
                spans.append(r.span)
        return spans
    # fallback
    spans: List[Tuple[int, int]] = []
    for rx in (EMAIL_RE, PHONE_RE, CARD_RE):
        for m in rx.finditer(text):
            spans.append((m.start(), m.end()))
    return spans

def _read_one(path: Path) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml") and yaml is not None:
        return yaml.safe_load(raw)  # type: ignore
    try:
        return json.loads(raw)
    except Exception as e:
        raise ValueError(f"Cannot parse {path}: {e}") from e

def _iter_inputs(paths: List[Path]) -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []
    for p in paths:
        if str(p) == "-":
            raw = sys.stdin.read()
            try:
                docs.append(json.loads(raw))
            except Exception:
                if yaml is None:
                    raise ValueError("STDIN is not valid JSON and PyYAML is not installed")
                docs.append(yaml.safe_load(raw))  # type: ignore
        else:
            docs.append(_read_one(p))
    return docs

def _collect_participants(doc: Dict[str, Any]) -> Dict[str, str]:
    res: Dict[str, str] = {}
    for k in ("participants", "actors"):
        arr = doc.get(k) or []
        if isinstance(arr, list):
            for a in arr:
                aid = str(_safe_get(a, "id", default=_safe_get(a, "participant_id", default=None)) or "")
                name = _safe_get(a, "displayName", default=_safe_get(a, "display_name", default=None))
                if aid and name:
                    res[aid] = name
    return res

def _compile_from_dialogue(doc: Dict[str, Any]) -> List[Msg]:
    dialogue_id = str(doc.get("dialogue_id") or doc.get("id") or "")
    parts = _collect_participants(doc)
    msgs: List[Msg] = []
    for t in (doc.get("turns") or []):
        ts = _parse_ts(t.get("created_at") or t.get("occurredAt"))
        role = _role_from_actor_enum(t.get("actor"))
        turn_id = str(t.get("turn_id") or t.get("id") or "")
        actor_id = str(t.get("participant_id") or t.get("actorId") or "")
        actor_name = parts.get(actor_id) or None
        text = t.get("text")
        data = t.get("data")
        if text is None:
            content = t.get("content") or {}
            if content.get("kind") == "text":
                text = content.get("text")
            elif content.get("kind") == "data":
                data = content.get("data")
        msgs.append(Msg(
            dialogue_id=dialogue_id, turn_id=turn_id, ts=ts, role=role, actor_id=actor_id,
            actor_name=actor_name, text=text, data=data, tags=t.get("tags") or []
        ))
    return msgs

def _compile_from_timeline(doc: Dict[str, Any]) -> List[Msg]:
    timeline_id = str(doc.get("id") or doc.get("dialogue_id") or "")
    parts = _collect_participants(doc)
    msgs: List[Msg] = []
    for ev in (doc.get("events") or []):
        etype = ev.get("type")
        if etype not in ("message_posted", "tool_result", "tool_called"):
            continue
        ts = _parse_ts(ev.get("occurredAt"))
        actor_id = str(ev.get("actorId") or _safe_get(ev, "actor", "id", default="") or "")
        actor_name = parts.get(actor_id) or _safe_get(ev, "actor", "displayName", default=None)
        if etype == "message_posted":
            content = ev.get("content") or {}
            text = content.get("text") if content.get("kind") == "text" else None
            msgs.append(Msg(
                dialogue_id=timeline_id, turn_id=str(ev.get("id") or ""), ts=ts,
                role=_role_from_event_actorname(actor_name), actor_id=actor_id, actor_name=actor_name,
                text=text, data=None, tags=ev.get("tags") or []
            ))
        else:
            # tool events -> data
            content = ev.get("content") or {}
            data = content.get("data") if content.get("kind") == "data" else {"event": etype, "payload": content}
            msgs.append(Msg(
                dialogue_id=timeline_id, turn_id=str(ev.get("id") or ""), ts=ts,
                role="tool", actor_id=actor_id, actor_name=actor_name,
                text=None, data=data, tags=ev.get("tags") or []
            ))
    return msgs

def _compile_messages(doc: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[dt.datetime], Optional[dt.datetime], Dict[str, str], List[Msg], Dict[str, int]]:
    # header
    dialogue_id = str(doc.get("dialogue_id") or doc.get("id") or doc.get("dialogue", {}).get("dialogue_id") or "")
    title = doc.get("title") or _safe_get(doc, "dialogue", "title", default=None)
    created_at = doc.get("created_at") or doc.get("createdAt") or _safe_get(doc, "dialogue", "created_at", default=None)
    updated_at = doc.get("updated_at") or doc.get("updatedAt") or _safe_get(doc, "dialogue", "updated_at", default=None)
    created_at_dt = _parse_ts(created_at) if created_at else None
    updated_at_dt = _parse_ts(updated_at) if updated_at else None
    participants = _collect_participants(doc) or _collect_participants(doc.get("dialogue") or {})

    # payload shape detection
    msgs: List[Msg] = []
    if isinstance(doc.get("turns"), list) or isinstance(_safe_get(doc, "dialogue", "turns", default=None), list):
        base = doc if isinstance(doc.get("turns"), list) else (doc.get("dialogue") or {})
        msgs.extend(_compile_from_dialogue(base))
        if not dialogue_id:
            dialogue_id = str(base.get("dialogue_id") or base.get("id") or "")
    if isinstance(doc.get("events"), list):
        msgs.extend(_compile_from_timeline(doc))

    # usage total (optional)
    usage = (doc.get("usage_total") or _safe_get(doc, "dialogue", "usage_total", default={})) or {}
    utotal = {
        "prompt_tokens": int(usage.get("prompt_tokens") or 0),
        "completion_tokens": int(usage.get("completion_tokens") or 0),
        "total_tokens": int(usage.get("total_tokens") or 0),
    }
    return dialogue_id, title, created_at_dt, updated_at_dt, participants, msgs, utotal

def _dedupe_and_sort(msgs: List[Msg]) -> List[Msg]:
    seen: set[Tuple[str, Optional[str]]] = set()
    out: List[Msg] = []
    for m in msgs:
        key = (m.dialogue_id, m.turn_id)
        if m.turn_id and key in seen:
            continue
        seen.add(key)
        out.append(m)
    out.sort(key=lambda m: (m.ts, m.turn_id or ""))
    return out

def _apply_actor_alias(msgs: List[Msg], aliases: Dict[str, str]) -> None:
    for m in msgs:
        if m.actor_id and m.actor_id in aliases:
            m.actor_name = aliases[m.actor_id]

def _mask_msgs(msgs: List[Msg]) -> None:
    for m in msgs:
        if m.text:
            spans = _detect_pii_spans(m.text)
            if spans:
                m.text = mask_pii(m.text, spans)

def _split_by_gap(msgs: List[Msg], gap: Optional[str]) -> List[List[Msg]]:
    if not gap:
        return [msgs]
    # parse simple duration: e.g., "30m", "2h"
    m = re.match(r"^(\d+)(ms|s|m|h|d)$", gap)
    if not m:
        return [msgs]
    qty, unit = int(m.group(1)), m.group(2)
    mult = {"ms": 1/1000, "s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    thr = qty * mult
    sessions: List[List[Msg]] = []
    cur: List[Msg] = []
    prev: Optional[dt.datetime] = None
    for m in msgs:
        if prev and (m.ts - prev).total_seconds() > thr and cur:
            sessions.append(cur)
            cur = []
        cur.append(m)
        prev = m.ts
    if cur:
        sessions.append(cur)
    return sessions

def _format_md(bundle: CompileResult, sessions: List[List[Msg]]) -> str:
    hdr = []
    hdr.append(f"# Dialogue {bundle.dialogue_id}")
    if bundle.title:
        hdr.append(f"**Title:** {bundle.title}")
    if bundle.created_at:
        hdr.append(f"**Created:** {bundle.created_at.isoformat().replace('+00:00', 'Z')}")
    if bundle.updated_at:
        hdr.append(f"**Updated:** {bundle.updated_at.isoformat().replace('+00:00', 'Z')}")
    if bundle.usage_total:
        ut = bundle.usage_total
        hdr.append(f"**Usage:** prompt={ut.get('prompt_tokens',0)} completion={ut.get('completion_tokens',0)} total={ut.get('total_tokens',0)}")
    if bundle.participants:
        plist = ", ".join([f"{v} ({k})" for k, v in bundle.participants.items()])
        hdr.append(f"**Participants:** {plist}")
    out = ["\n".join(hdr), ""]
    for i, sess in enumerate(sessions, 1):
        if len(sessions) > 1:
            out.append(f"## Session {i}")
        for m in sess:
            ts = m.ts.isoformat().replace("+00:00", "Z")
            who = m.actor_name or m.role
            out.append(f"**{ts} — {who}:**")
            if m.text:
                out.append("")
                out.append(textwrap.indent(m.text.strip(), "  "))
            if m.data is not None and not m.text:
                out.append("")
                out.append("  ```json")
                out.append("  " + json.dumps(m.data, ensure_ascii=False, indent=2))
                out.append("  ```")
            if m.tags:
                out.append(f"  _tags: {', '.join(m.tags)}_")
            out.append("")
    return "\n".join(out).rstrip() + "\n"

def _format_json(bundle: CompileResult, sessions: List[List[Msg]]) -> str:
    payload = {
        "dialogue_id": bundle.dialogue_id,
        "title": bundle.title,
        "created_at": bundle.created_at.isoformat().replace("+00:00", "Z") if bundle.created_at else None,
        "updated_at": bundle.updated_at.isoformat().replace("+00:00", "Z") if bundle.updated_at else None,
        "participants": bundle.participants,
        "usage_total": bundle.usage_total,
        "sessions": [
            [
                {
                    "turn_id": m.turn_id,
                    "ts": m.ts.isoformat().replace("+00:00", "Z"),
                    "role": m.role,
                    "actor_id": m.actor_id,
                    "actor_name": m.actor_name,
                    "text": m.text,
                    "data": m.data,
                    "tags": m.tags,
                }
                for m in sess
            ]
            for sess in sessions
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"

def _format_jsonl(bundle: CompileResult, sessions: List[List[Msg]]) -> str:
    lines = []
    for sess in sessions:
        for m in sess:
            lines.append(json.dumps({
                "dialogue_id": bundle.dialogue_id,
                "turn_id": m.turn_id,
                "ts": m.ts.isoformat().replace("+00:00", "Z"),
                "role": m.role,
                "actor": m.actor_name or m.actor_id or m.role,
                "text": m.text,
                "data": m.data,
                "tags": m.tags,
            }, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")

def _format_chatml(bundle: CompileResult, sessions: List[List[Msg]]) -> str:
    # OpenAI-style messages for each session; по одному JSON-объекту в строке
    role_map = {"system","user","assistant","tool"}
    lines = []
    for sess in sessions:
        messages = []
        # опционально добавим заголовок как system
        if bundle.title:
            messages.append({"role": "system", "content": f"Title: {bundle.title}"})
        for m in sess:
            role = m.role if m.role in role_map else "user"
            if role == "tool" and m.data is not None and not m.text:
                content = json.dumps(m.data, ensure_ascii=False)
            else:
                content = m.text or (json.dumps(m.data, ensure_ascii=False) if m.data is not None else "")
            messages.append({"role": role, "content": content})
        lines.append(json.dumps({"dialogue_id": bundle.dialogue_id, "messages": messages}, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


# ---------- CLI ----------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="compile_dialogue",
        description="Compile Mythos dialogue/timeline into md/json/jsonl/chatml",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-i", "--input", action="append", required=True, help="Входной JSON/YAML файл(ы) или '-' для STDIN")
    ap.add_argument("-o", "--out", default="-", help="Файл вывода или '-' для STDOUT")
    ap.add_argument("-f", "--format", choices=["md", "json", "jsonl", "chatml"], default="md", help="Формат вывода")
    ap.add_argument("--mask-pii", action="store_true", help="Маскировать PII в текстах")
    ap.add_argument("--split-gap", default=None, help="Разбивать на сессии при простое больше зазора (например, 30m, 2h)")
    ap.add_argument("--max", type=int, default=None, help="Ограничить количество сообщений после сортировки")
    ap.add_argument("--actor-alias", default=None, help="JSON-словарь для переименования акторов по actor_id")
    ap.add_argument("--strict", action="store_true", help="Строгий режим: падать при пустом диалоге/несогласованных id")
    args = ap.parse_args(argv)

    # входные файлы
    paths = [Path(p) for p in args.input]
    try:
        docs = _iter_inputs(paths)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    # компиляция (поддержка нескольких документов одного диалога)
    all_msgs: List[Msg] = []
    header_id: Optional[str] = None
    title: Optional[str] = None
    created_at: Optional[dt.datetime] = None
    updated_at: Optional[dt.datetime] = None
    participants: Dict[str, str] = {}
    usage_total: Dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    for doc in docs:
        d_id, d_title, d_created, d_updated, d_part, msgs, utotal = _compile_messages(doc)
        if not d_id:
            if args.strict:
                print("ERROR: dialogue_id is missing in input", file=sys.stderr)
                return 1
        header_id = header_id or d_id
        if args.strict and header_id and d_id and d_id != header_id:
            print(f"ERROR: multiple inputs have different dialogue_id: {header_id} vs {d_id}", file=sys.stderr)
            return 1
        title = title or d_title
        created_at = created_at or d_created
        # updated_at — берём максимальный
        if d_updated and (updated_at is None or d_updated > updated_at):
            updated_at = d_updated
        participants.update(d_part)
        usage_total = {
            "prompt_tokens": usage_total.get("prompt_tokens", 0) + utotal.get("prompt_tokens", 0),
            "completion_tokens": usage_total.get("completion_tokens", 0) + utotal.get("completion_tokens", 0),
            "total_tokens": usage_total.get("total_tokens", 0) + utotal.get("total_tokens", 0),
        }
        all_msgs.extend(msgs)

    if not all_msgs:
        if args.strict:
            print("ERROR: no messages found in inputs", file=sys.stderr)
            return 1

    # сортировка и дедупликация
    all_msgs = _dedupe_and_sort(all_msgs)

    # ограничение
    if isinstance(args.max, int) and args.max > 0:
        all_msgs = all_msgs[: args.max]

    # алиасы акторов
    if args.actor_alias:
        try:
            aliases = json.loads(args.actor_alias)
            if not isinstance(aliases, dict):
                raise ValueError("actor-alias must be a JSON object")
            _apply_actor_alias(all_msgs, {str(k): str(v) for k, v in aliases.items()})
        except Exception as e:
            print(f"ERROR: invalid --actor-alias: {e}", file=sys.stderr)
            return 1

    # маскирование PII
    if args.mask_pii:
        _mask_msgs(all_msgs)

    # разбиение на сессии
    sessions = _split_by_gap(all_msgs, args.split_gap)

    bundle = CompileResult(
        dialogue_id=header_id or (all_msgs[0].dialogue_id if all_msgs else "unknown"),
        title=title,
        created_at=created_at,
        updated_at=updated_at or (all_msgs[-1].ts if all_msgs else None),
        participants=participants,
        messages=all_msgs,
        usage_total=usage_total,
    )

    # форматирование
    try:
        if args.format == "md":
            rendered = _format_md(bundle, sessions)
        elif args.format == "json":
            rendered = _format_json(bundle, sessions)
        elif args.format == "jsonl":
            rendered = _format_jsonl(bundle, sessions)
        else:  # chatml
            rendered = _format_chatml(bundle, sessions)
    except Exception as e:
        print(f"ERROR: render failed: {e}", file=sys.stderr)
        return 3

    # вывод
    try:
        if args.out == "-" or args.out == "":
            sys.stdout.write(rendered)
        else:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(rendered, encoding="utf-8")
    except Exception as e:
        print(f"ERROR: cannot write output: {e}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
