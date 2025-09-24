#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VeilMind — Synthetic Text Generator CLI (industrial)

Назначение:
    Массовая генерация синтетических текстов для тестов/датасетов/демо с детерминированностью и пост-фильтрацией безопасности.

Зависимости:
    - Стандартная библиотека Python 3.10+.
    - Опционально: PyYAML (если хотите YAML-конфиг/плейсхолдеры); gzip поддерживается стандартной библиотекой.
    - В проекте должны быть доступны:
        veilmind.synthetic.text: TextSpec, NoiseSpec, TextSynthEngine
        veilmind.prompt_guard.safety_filters: guard_output (опционально)

Примеры:
    # 100 предложений EN, детерминированно, в stdout (text)
    python -m cli.tools.gen_synthetic --count 100 --mode sentence --locale en --seed 42

    # 1K параграфов RU с корпусом и шаблонами из YAML, jsonl в файл с gzip
    python -m cli.tools.gen_synthetic \
        --count 1000 --mode paragraph --locale ru --seed 7 \
        --config configs/synth.yaml --output out/synth.jsonl.gz --format jsonl

    # Применить безопасность: блокировать опасные записи, отчет в stderr
    python -m cli.tools.gen_synthetic --count 200 --safety block --seed 123

Формат YAML-конфига (пример):
    locale: en
    mode: paragraph
    target_sentences: 2
    target_paragraphs: 1
    min_words_per_sentence: 6
    max_words_per_sentence: 14
    markov_weight: 0.6
    noise:
      typo_rate: 0.01
      case_flip_rate: 0.005
      whitespace_jitter: 0.01
      confusable_rate: 0.0
      max_typos_per_text: 3
    templates:
      - "Support ticket: {paragraph}"
      - "Contact {name} at {email} re {sentence}"
    placeholders:
      product: ["Core", "Gateway", "Agent"]
    forbid_terms: ["password", "secret"]

Коды возврата:
    0  — успех, записи сгенерированы (включая возможные FLAG).
    2  — часть записей заблокирована в режиме --safety block.
    3  — критическая ошибка конфигурации/окружения.

Автор: VeilMind Core CLI
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --------------------------- Импорты проекта ---------------------------
try:
    from veilmind.synthetic.text import TextSpec, NoiseSpec, TextSynthEngine
except Exception as e:
    print("Missing dependency: veilmind.synthetic.text (TextSpec, NoiseSpec, TextSynthEngine).", file=sys.stderr)
    print(f"Import error: {e}", file=sys.stderr)
    sys.exit(3)

try:
    # Опциональная безопасность
    from veilmind.prompt_guard import safety_filters as pg  # guard_output(), SafetyConfig
    _PG_OK = True
except Exception:
    _PG_OK = False

try:
    import yaml  # type: ignore
    _YAML_OK = True
except Exception:
    yaml = None  # type: ignore
    _YAML_OK = False

LOG = logging.getLogger("veilmind.cli.gen_synth")


# --------------------------- Аргументы ---------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gen_synthetic",
        description="Generate synthetic texts with deterministic seed and safety post-filter."
    )
    p.add_argument("--config", type=str, default="", help="YAML/JSON файл конфигурации (опционально).")
    p.add_argument("--output", type=str, default="-", help="Путь к выходному файлу или '-' для stdout. '.gz' => gzip.")
    p.add_argument("--format", choices=["text", "jsonl"], default="text", help="Формат вывода.")
    p.add_argument("--mode", choices=["sentence", "paragraph", "document", "stream"], default="sentence", help="Режим генерации.")
    p.add_argument("--count", type=int, default=1, help="Количество записей (для stream — это число событий).")
    p.add_argument("--locale", choices=["en", "ru"], default="en", help="Локаль генерации.")
    p.add_argument("--seed", type=int, default=0, help="Базовый seed для детерминизма. 0 => недетерминированно.")
    p.add_argument("--corpus", type=str, default="", help="Путь к текстовому корпусу для Markov (опц.).")
    p.add_argument("--templates", type=str, default="", help="Путь к YAML/JSON файлу со списком шаблонов (опц.).")
    p.add_argument("--placeholders", type=str, default="", help="Путь к YAML/JSON файлу с плейсхолдерами {key:[...]}.")
    p.add_argument("--forbid-terms", type=str, default="", help="Путь к файлу со списком запрещенных терминов (по строке).")
    p.add_argument("--enforce-regex", type=str, default="", help="Регекс, которому должен соответствовать итоговый текст.")
    p.add_argument("--target-sentences", type=int, default=1, help="Число предложений в параграфе.")
    p.add_argument("--target-paragraphs", type=int, default=1, help="Число параграфов в документе.")
    p.add_argument("--min-words", type=int, default=6, help="Мин. слов в предложении.")
    p.add_argument("--max-words", type=int, default=16, help="Макс. слов в предложении.")
    p.add_argument("--max-chars", type=int, default=800, help="Глобальный предел символов.")
    p.add_argument("--max-words-total", type=int, default=160, help="Глобальный предел слов.")
    p.add_argument("--markov-weight", type=float, default=0.5, help="Доля слов из Markov (0..1).")
    # Шум
    p.add_argument("--typo-rate", type=float, default=0.0, help="Вероятность опечатки на символ.")
    p.add_argument("--case-flip-rate", type=float, default=0.0, help="Вероятность смены регистра на символ.")
    p.add_argument("--whitespace-jitter", type=float, default=0.0, help="Вероятность лишнего пробела.")
    p.add_argument("--confusable-rate", type=float, default=0.0, help="Вероятность подмены confusable.")
    p.add_argument("--max-typos", type=int, default=5, help="Макс. опечаток на текст.")
    # Безопасность
    p.add_argument("--safety", choices=["off", "flag", "block"], default="flag",
                   help="off — не фильтровать; flag — помечать/редактировать; block — блокировать опасные записи.")
    p.add_argument("--safety-allow-emails", action="store_true", help="Разрешить email (без редакции) в safety.")
    p.add_argument("--safety-allow-phones", action="store_true", help="Разрешить телефоны (без редакции) в safety.")
    # Прочее
    p.add_argument("--entity-id", type=str, default="default", help="Ключ сущности для консистентных {name}/{email}/... .")
    p.add_argument("--flush-every", type=int, default=0, help="Принудительный flush каждые N записей (0=по умолчанию).")
    p.add_argument("--log-level", type=str, default="INFO", help="Уровень логирования.")
    return p


# --------------------------- Конфигурация ---------------------------
def _load_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _load_yaml_or_json(path: str) -> Any:
    if not path:
        return None
    text = _load_text(path)
    if path.lower().endswith((".yaml", ".yml")):
        if not _YAML_OK:
            raise RuntimeError("PyYAML недоступен, а файл конфигурации в YAML.")
        return yaml.safe_load(text)  # type: ignore
    return json.loads(text)

def _load_lines(path: str) -> List[str]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip()]

@dataclass
class RunSpec:
    mode: str
    count: int
    engine: TextSynthEngine
    entity_id: str
    safety_mode: str
    safety_cfg: Optional[Any]  # pg.SafetyConfig при наличии
    format: str
    enforce_regex: Optional[str]


def _merge_spec_from_config(args: argparse.Namespace) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    if args.config:
        raw = _load_yaml_or_json(args.config)
        if isinstance(raw, dict):
            cfg.update(raw)
        elif raw is not None:
            raise ValueError("Ожидался объект верхнего уровня в файле конфигурации.")
    # Аргументы CLI имеют приоритет
    ov = lambda k, v: cfg.__setitem__(k, v)  # noqa: E731
    ov("locale", args.locale)
    ov("mode", args.mode)
    ov("target_sentences", args.target_sentences)
    ov("target_paragraphs", args.target_paragraphs)
    ov("min_words_per_sentence", args.min_words)
    ov("max_words_per_sentence", args.max_words)
    ov("max_chars", args.max_chars)
    ov("max_words", args.max_words_total)
    ov("markov_weight", args.markov_weight)
    # noise
    cfg.setdefault("noise", {})
    cfg["noise"].update({
        "typo_rate": args.typo_rate,
        "case_flip_rate": args.case_flip_rate,
        "whitespace_jitter": args.whitespace_jitter,
        "confusable_rate": args.confusable_rate,
        "max_typos_per_text": args.max_typos,
    })
    # enforce_regex
    if args.enforce_regex:
        ov("enforce_regex", args.enforce_regex)
    return cfg


def _build_engine(cfg: Dict[str, Any], args: argparse.Namespace) -> TextSynthEngine:
    # корпус
    corpus_text = None
    if args.corpus:
        corpus_text = _load_text(args.corpus)

    # шаблоны
    templates = None
    if args.templates:
        t_raw = _load_yaml_or_json(args.templates)
        if isinstance(t_raw, list):
            templates = [str(x) for x in t_raw if x]
        else:
            raise ValueError("Файл --templates должен содержать список строк.")

    # плейсхолдеры
    placeholders: Dict[str, List[str]] = {}
    if args.placeholders:
        pl_raw = _load_yaml_or_json(args.placeholders)
        if isinstance(pl_raw, dict):
            placeholders = {str(k): list(v) for k, v in pl_raw.items() if isinstance(v, list)}
        else:
            raise ValueError("Файл --placeholders должен содержать объект {key:[values]}.")

    # запреты
    forbid_terms = _load_lines(args.forbid_terms) if args.forbid_terms else cfg.get("forbid_terms", [])

    # NoiseSpec
    ncfg = cfg.get("noise", {}) or {}
    noise = NoiseSpec(
        typo_rate=float(ncfg.get("typo_rate", 0.0)),
        case_flip_rate=float(ncfg.get("case_flip_rate", 0.0)),
        whitespace_jitter=float(ncfg.get("whitespace_jitter", 0.0)),
        confusable_rate=float(ncfg.get("confusable_rate", 0.0)),
        max_typos_per_text=int(ncfg.get("max_typos_per_text", 5)),
    )

    # TextSpec
    spec = TextSpec(
        locale=str(cfg.get("locale", "en")),
        style=str(cfg.get("style", "lorem")),
        target_sentences=int(cfg.get("target_sentences", 1)),
        target_paragraphs=int(cfg.get("target_paragraphs", 1)),
        min_words_per_sentence=int(cfg.get("min_words_per_sentence", 6)),
        max_words_per_sentence=int(cfg.get("max_words_per_sentence", 16)),
        corpus=corpus_text,
        templates=templates,
        placeholders=placeholders,
        forbid_terms=list(forbid_terms or []),
        enforce_regex=str(cfg.get("enforce_regex", "")) or None,
        seed=int(args.seed) if int(args.seed) != 0 else None,
        noise=noise,
        max_chars=int(cfg.get("max_chars", 800)),
        max_words=int(cfg.get("max_words", 160)),
        markov_order=int(cfg.get("markov_order", 2)),
        markov_weight=float(cfg.get("markov_weight", 0.5)),
    )

    return TextSynthEngine(spec)


def _open_output(path: str):
    if path == "-" or not path:
        return sys.stdout, False
    # создаем директорию
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if path.endswith(".gz"):
        # текстовый gzip writer в utf-8
        gz = gzip.open(path, "wt", encoding="utf-8", newline="\n")
        return gz, True
    f = open(path, "w", encoding="utf-8", newline="\n")
    return f, True


# --------------------------- Генерация и фильтрация ---------------------------
def _build_safety(args: argparse.Namespace):
    if args.safety == "off" or not _PG_OK:
        return None, None
    cfg = pg.SafetyConfig(
        allow_emails=bool(args.safety_allow_emails),
        allow_phones=bool(args.safety_allow_phones),
    )
    return args.safety, cfg


def _record_obj(idx: int, text: str, args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "id": idx,
        "text": text,
        "locale": args.locale,
        "mode": args.mode,
        "seed": int(args.seed),
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def _write_line(w, s: str):
    w.write(s)
    if not s.endswith("\n"):
        w.write("\n")


def run(spec: RunSpec, args: argparse.Namespace) -> Tuple[int, int, int]:
    """
    Возвращает (written, flagged, blocked).
    """
    written = 0
    flagged = 0
    blocked = 0

    eng = spec.engine
    mode = spec.mode
    fmt = spec.format
    entity_id = spec.entity_id

    out, need_close = _open_output(args.output)
    try:
        for i in range(max(0, spec.count)):
            # Детерминированность: если seed задан, переназначаем seed на базе base_seed + i
            if eng.spec.seed is not None:
                # создаем новый engine с deriving-seed, чтобы не копить состояние
                eng = TextSynthEngine(eng.spec.__class__(**{**eng.spec.__dict__, "seed": int(eng.spec.seed) + i}))  # shallow copy

            if mode == "sentence":
                txt = eng.sentence(entity_id)
            elif mode == "paragraph":
                txt = eng.paragraph(entity_id)
            elif mode == "document":
                txt = eng.document(entity_id)
            else:
                # stream трактуем как count предложений
                txt = eng.sentence(entity_id)

            # Пост-фильтрация
            decision = "ALLOW"
            redacted = txt
            report = None
            if spec.safety_mode and _PG_OK:
                redacted, report = pg.guard_output(txt, cfg=spec.safety_cfg)
                decision = report.decision
                if decision == "BLOCK":
                    blocked += 1
                    if args.format == "jsonl":
                        obj = _record_obj(i, "", args)
                        obj["safety"] = {"decision": decision, "score": report.total_score, "categories": report.categories}
                        _write_line(out, json.dumps(obj, ensure_ascii=False))
                        written += 1  # фиксируем запись, даже если пустой текст, чтобы сохранить соответствие индексам
                    else:
                        # text формат: пропускаем сам текст, но пишем мета-комментарий
                        _write_line(out, f"[BLOCKED id={i} score={report.total_score} cats={','.join(report.categories)}]")
                        written += 1
                    continue
                if decision == "FLAG":
                    flagged += 1

            # Запись
            if fmt == "jsonl":
                obj = _record_obj(i, redacted, args)
                if report:
                    obj["safety"] = {"decision": decision, "score": report.total_score, "categories": report.categories}
                _write_line(out, json.dumps(obj, ensure_ascii=False))
            else:
                _write_line(out, redacted)

            written += 1

            if spec.enforce_regex:
                # если задан регекс, убедимся, что текущий redacted соответствует; иначе логируем
                try:
                    pat = re.compile(spec.enforce_regex)
                    if not pat.search(redacted):
                        LOG.warning("enforce_regex_miss", extra={"idx": i})
                except re.error:
                    LOG.error("invalid_enforce_regex", extra={"regex": spec.enforce_regex})

            if args.flush_every and (i + 1) % args.flush_every == 0:
                out.flush()

    finally:
        if need_close:
            out.close()

    return written, flagged, blocked


# --------------------------- Точка входа ---------------------------
def _setup_logging(level: str):
    lvl = (level or "INFO").upper()
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.log_level)

    try:
        cfg = _merge_spec_from_config(args)
        engine = _build_engine(cfg, args)
        safety_mode, safety_cfg = _build_safety(args)
        rs = RunSpec(
            mode=args.mode,
            count=int(args.count),
            engine=engine,
            entity_id=args.entity_id,
            safety_mode=safety_mode or "off",
            safety_cfg=safety_cfg,
            format=args.format,
            enforce_regex=cfg.get("enforce_regex"),
        )
        t0 = time.time()
        written, flagged, blocked = run(rs, args)
        dt = time.time() - t0
        LOG.info("done", extra={"written": written, "flagged": flagged, "blocked": blocked, "seconds": round(dt, 3)})
        if blocked > 0 and (args.safety == "block"):
            return 2
        return 0
    except KeyboardInterrupt:
        LOG.warning("interrupted")
        return 130
    except Exception as e:
        LOG.exception("fatal_error")
        print(f"ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
