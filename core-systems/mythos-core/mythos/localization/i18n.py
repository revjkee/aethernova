# -*- coding: utf-8 -*-
"""
Industrial i18n for Mythos Core.

Features:
- BCP-47 locale parsing, negotiation (Accept-Language) and fallback chain.
- Domain-based catalogs (messages/errors/…); JSON and YAML loaders.
- Thread/async-safe caches with atomic hot-reload on mtime change.
- ICU-like plural: {count, plural, =0{…} one{…} few{…} many{…} other{…}}, '#' -> localized count.
- Safe interpolation for {name} placeholders with explicit args.
- Context-local current locale via contextvars and context manager.
- Optional formatting via Babel (numbers, currency, dates, timedelta). Graceful fallback if missing.
- Missing-keys sink with counters (for observability).
- Tiny dependency surface; Babel/YAML are optional.

Catalog layout (example):
  <base_path>/
    en/
      messages.json
      errors.yaml
    ru/
      messages.json
      errors.yaml

Message examples:
  "greeting": "Hello, {name}!"
  "items": "{count, plural, =0{No items} one{One item} few{# items} many{# items} other{# items}}"
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

# Optional dependencies
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

try:
    from babel.core import Locale as _BabelLocale  # type: ignore
    from babel.numbers import format_decimal as _fmt_decimal  # type: ignore
    from babel.numbers import format_currency as _fmt_currency  # type: ignore
    from babel.dates import format_datetime as _fmt_datetime  # type: ignore
    _HAVE_BABEL = True
except Exception:  # pragma: no cover
    _BABEL = None
    _HAVE_BABEL = False

# ------------------------------- Configuration ----------------------------------------

@dataclass(frozen=True)
class I18nConfig:
    base_path: Path                      # root folder of catalogs
    default_locale: str = "en"
    domains: Tuple[str, ...] = ("messages", "errors")
    auto_reload: bool = False            # check mtimes on each lookup
    cache_ttl_seconds: int = 300         # soft TTL for compiled entries

# ------------------------------ Internal structures -----------------------------------

@dataclass
class _Catalog:
    data: Dict[str, str]                 # flat dotted keys -> message
    mtime: float                         # latest mtime of domain files

@dataclass
class _CompiledEntry:
    # Cached compiled message (either plain or plural AST)
    is_plural: bool
    ast: Any
    compiled_at: float

# ------------------------------ Locale handling ---------------------------------------

_LOCALE_CTX: contextvars.ContextVar[str] = contextvars.ContextVar("current_locale", default="en")

_LOCALE_RE = re.compile(r"^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$")

def normalize_locale(loc: str) -> str:
    """Normalize 'ru_RU' / 'ru-ru' -> 'ru-RU'."""
    parts = re.split(r"[-_]", loc.strip())
    if not parts or not parts[0]:
        return "en"
    primary = parts[0].lower()
    rest = [p.upper() if len(p) in (2, 3) else p.title() for p in parts[1:]]
    return "-".join([primary] + rest)

def locale_chain(loc: str, default: str) -> List[str]:
    """ru-RU -> ['ru-RU','ru',default]. Deduplicate preserving order."""
    loc = normalize_locale(loc)
    default = normalize_locale(default)
    items = [loc]
    if "-" in loc:
        items.append(loc.split("-")[0])
    if default not in items:
        items.append(default)
    seen: set = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

def parse_accept_language(header: str, supported: Iterable[str], default: str) -> str:
    """
    RFC 7231 parsing with q-weights; matches against supported (normalized).
    """
    supported_norm = [normalize_locale(s) for s in supported]
    choices: List[Tuple[str, float]] = []
    for part in header.split(","):
        sub = part.strip()
        if not sub:
            continue
        if ";q=" in sub:
            lang, q = sub.split(";q=", 1)
            try:
                qv = float(q)
            except ValueError:
                qv = 0.0
        else:
            lang, qv = sub, 1.0
        lang = normalize_locale(lang)
        # try exact, then primary tag
        match = None
        if lang in supported_norm:
            match = lang
        else:
            primary = lang.split("-")[0]
            for s in supported_norm:
                if s == primary:
                    match = s
                    break
        if match:
            choices.append((match, qv))
    if choices:
        choices.sort(key=lambda x: x[1], reverse=True)
        return choices[0][0]
    return normalize_locale(default)

# ----------------------------- Plural rules (fallback) --------------------------------

def _plural_category_builtin(n: float, locale: str) -> str:
    """
    Minimal CLDR-like fallback for common locales when Babel is absent.
    Supports: en, de, es, it, pt, nl (one/other); fr (0/1 -> one); ru/uk/by (one/few/many/other);
    pl (one/few/many/other simplified). Defaults to English.
    """
    l = normalize_locale(locale).split("-")[0]
    i = int(n)
    if l in {"en", "de", "es", "it", "pt", "nl", "sv"}:
        return "one" if i == 1 else "other"
    if l in {"fr"}:
        return "one" if i in (0, 1) else "other"
    if l in {"ru", "uk", "be"}:
        mod10 = i % 10
        mod100 = i % 100
        if mod10 == 1 and mod100 != 11:
            return "one"
        if mod10 in {2, 3, 4} and not (12 <= mod100 <= 14):
            return "few"
        if mod10 == 0 or mod10 in {5, 6, 7, 8, 9} or (11 <= mod100 <= 14):
            return "many"
        return "other"
    if l in {"pl"}:
        mod10 = i % 10
        mod100 = i % 100
        if i == 1:
            return "one"
        if 2 <= mod10 <= 4 and not (12 <= mod100 <= 14):
            return "few"
        if mod10 in {0, 1} or 5 <= mod10 <= 9 or (12 <= mod100 <= 14):
            return "many"
        return "other"
    if l in {"cs", "sk"}:
        if i == 1:
            return "one"
        if 2 <= i <= 4:
            return "few"
        return "other"
    return "one" if i == 1 else "other"

def _plural_category(n: float, locale: str) -> str:
    if _HAVE_BABEL:
        try:
            loc = _BabelLocale.parse(locale)
            # babel >=2.10: Locale.plural_form
            return str(loc.plural_form(n))  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover
            pass
    return _plural_category_builtin(n, locale)

def _format_number(n: float, locale: str) -> str:
    if _HAVE_BABEL:
        try:
            return _fmt_decimal(n, locale=locale)  # type: ignore
        except Exception:  # pragma: no cover
            pass
    # naive fallback
    if int(n) == n:
        return str(int(n))
    return str(n)

# ---------------------------- Plural message parsing ----------------------------------

# Pattern for ICU-like plural: {var, plural, =0{...} one{...} few{...} many{...} other{...}}
# We implement a light parser that supports nesting via brace counting.

_BRACE_OPEN = "{"
_BRACE_CLOSE = "}"

class _PluralAST:
    __slots__ = ("var", "options")  # options: Dict[str, str] with keys like '=0', 'one', 'other'
    def __init__(self, var: str, options: Dict[str, str]) -> None:
        self.var = var
        self.options = options

def _parse_plural_segment(seg: str) -> _PluralAST:
    # seg contains "var, plural, ..." (already without outer braces)
    head, _, tail = seg.strip().partition(",")
    var = head.strip()
    if not var:
        raise ValueError("plural var missing")
    kind, _, opts = tail.strip().partition(",")
    if kind.strip() != "plural":
        raise ValueError("not a plural segment")
    options: Dict[str, str] = {}
    i = 0
    while i < len(opts):
        # skip spaces
        while i < len(opts) and opts[i].isspace():
            i += 1
        # read selector (=N or keyword)
        j = i
        while j < len(opts) and not opts[j].isspace() and opts[j] != _BRACE_OPEN:
            j += 1
        selector = opts[i:j]
        # expect '{'
        while j < len(opts) and opts[j].isspace():
            j += 1
        if j >= len(opts) or opts[j] != _BRACE_OPEN:
            raise ValueError("expected '{' after selector")
        j += 1
        # read until matching '}'
        level = 1
        k = j
        while k < len(opts) and level > 0:
            if opts[k] == _BRACE_OPEN:
                level += 1
            elif opts[k] == _BRACE_CLOSE:
                level -= 1
            k += 1
        chunk = opts[j : k - 1]
        options[selector] = chunk
        i = k
    return _PluralAST(var=var, options=options)

def _compile_message(msg: str) -> _CompiledEntry:
    # Detect top-level plural patterns and compile a single plural AST.
    # If multiple plural sections exist, we process them left-to-right at runtime.
    if "{", "plural" not in (msg, msg):  # tiny fast path
        return _CompiledEntry(is_plural=False, ast=msg, compiled_at=time.time())
    # Walk string and replace the first plural with AST marker; leave others as text for recursive compile.
    i = 0
    while i < len(msg):
        if msg[i] == _BRACE_OPEN:
            j = i + 1
            level = 1
            while j < len(msg) and level > 0:
                if msg[j] == _BRACE_OPEN:
                    level += 1
                elif msg[j] == _BRACE_CLOSE:
                    level -= 1
                j += 1
            inner = msg[i + 1 : j - 1]
            # heuristic: must contain ", plural,"
            if ", plural," in inner:
                ast = _parse_plural_segment(inner)
                before = msg[:i]
                after = msg[j:]
                return _CompiledEntry(
                    is_plural=True,
                    ast=(before, ast, after),
                    compiled_at=time.time(),
                )
            i = j
        else:
            i += 1
    return _CompiledEntry(is_plural=False, ast=msg, compiled_at=time.time())

def _render_compiled(entry: _CompiledEntry, args: Mapping[str, Any], locale: str) -> str:
    if not entry.is_plural:
        # simple interpolation {name}
        return _interpolate_text(entry.ast, args)
    before, ast, after = entry.ast  # type: ignore[misc]
    # find count
    if ast.var not in args:
        raise KeyError(f"missing plural var '{ast.var}'")
    n = args[ast.var]
    try:
        num = float(n)
    except Exception as e:
        raise ValueError(f"plural var '{ast.var}' is not a number") from e

    # select option
    explicit_key = f"={int(num)}"
    if explicit_key in ast.options:
        body = ast.options[explicit_key]
    else:
        cat = _plural_category(num, locale)
        body = ast.options.get(cat) or ast.options.get("other")
        if body is None:
            raise KeyError("plural option 'other' is required")
    # replace '#' with localized number
    body = body.replace("#", _format_number(num, locale))

    # The body may still contain nested plurals/placeholders
    rendered = _interpolate_text(body, args)
    # If nested plural present, recursively compile and render
    if ", plural," in rendered and "{" in rendered:
        nested = _compile_message(rendered)
        rendered = _render_compiled(nested, args, locale)
    return _interpolate_text(before, args) + rendered + _interpolate_text(after, args)

_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

def _interpolate_text(text: str, args: Mapping[str, Any]) -> str:
    def repl(m: re.Match[str]) -> str:
        key = m.group(1)
        if key in args:
            val = args[key]
            return str(val)
        # leave as-is for debugging missing arg
        return m.group(0)
    return _PLACEHOLDER_RE.sub(repl, text)

# ------------------------------ Catalog loader ----------------------------------------

def _flatten(obj: Mapping[str, Any], prefix: str = "") -> Dict[str, str]:
    """Flatten nested dicts into dotted keys."""
    out: Dict[str, str] = {}
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = str(v)
    return out

def _load_file(path: Path) -> Dict[str, str]:
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is not installed, can't load YAML catalogs")
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Catalog root must be an object: {path}")
    return _flatten(data)

# ------------------------------- I18n engine ------------------------------------------

class I18n:
    """
    Thread/async-safe i18n engine with domain catalogs and ICU-like plurals.
    """
    def __init__(self, cfg: I18nConfig) -> None:
        self.cfg = cfg
        self._lock = threading.RLock()
        # catalogs[(locale, domain)] = _Catalog
        self._catalogs: Dict[Tuple[str, str], _Catalog] = {}
        # compiled[(locale, domain, key)] = _CompiledEntry
        self._compiled: Dict[Tuple[str, str, str], _CompiledEntry] = {}
        # missing[(locale, domain, key)] = counter
        self._missing: Dict[Tuple[str, str, str], int] = {}

    # ------------------------ public API ------------------------

    def set_locale(self, locale: str) -> None:
        _LOCALE_CTX.set(normalize_locale(locale))

    @contextlib.contextmanager
    def use_locale(self, locale: str):
        token = _LOCALE_CTX.set(normalize_locale(locale))
        try:
            yield
        finally:
            _LOCALE_CTX.reset(token)

    def get_locale(self) -> str:
        return _LOCALE_CTX.get()

    def t(
        self,
        key: str,
        *,
        locale: Optional[str] = None,
        domain: str = "messages",
        **kwargs: Any,
    ) -> str:
        """
        Translate key with optional interpolation variables in kwargs.
        Supports ICU-like plural if message contains a plural block.
        """
        loc = normalize_locale(locale or self.get_locale() or self.cfg.default_locale)
        msg = self._lookup(loc, domain, key)
        entry = self._compile_if_needed(loc, domain, key, msg)
        return _render_compiled(entry, kwargs, loc)

    def tn(
        self,
        singular_key: str,
        plural_key: Optional[str] = None,
        count: int = 0,
        *,
        locale: Optional[str] = None,
        domain: str = "messages",
        **kwargs: Any,
    ) -> str:
        """
        Translate with explicit count. If the catalog has ICU plural at singular_key,
        it will be used. Otherwise:
         - if plural_key provided, pick singular/plural by rules;
         - else fallback to singular_key.
        """
        loc = normalize_locale(locale or self.get_locale() or self.cfg.default_locale)
        # Prefer ICU plural at singular_key
        msg = self._lookup(loc, domain, singular_key, missing_silent=True)
        if msg and "{", "plural," in (msg, msg):  # fast heuristic
            kwargs = {"count": count, **kwargs}
            entry = self._compile_if_needed(loc, domain, singular_key, msg)
            return _render_compiled(entry, kwargs, loc)

        # No ICU plural; choose between singular_key/plural_key
        cat = _plural_category(count, loc)
        key = singular_key if cat == "one" or plural_key is None else plural_key
        msg2 = self._lookup(loc, domain, key)
        return _interpolate_text(msg2, {"count": count, **kwargs})

    def format_number(self, n: float, *, locale: Optional[str] = None) -> str:
        return _format_number(n, normalize_locale(locale or self.get_locale() or self.cfg.default_locale))

    def format_currency(self, amount: float, currency: str, *, locale: Optional[str] = None) -> str:
        loc = normalize_locale(locale or self.get_locale() or self.cfg.default_locale)
        if _HAVE_BABEL:
            try:
                return _fmt_currency(amount, currency, locale=loc)  # type: ignore
            except Exception:  # pragma: no cover
                pass
        return f"{amount:.2f} {currency}"

    def format_datetime(self, dt, *, locale: Optional[str] = None, format: str = "medium") -> str:
        loc = normalize_locale(locale or self.get_locale() or self.cfg.default_locale)
        if _HAVE_BABEL:
            try:
                return _fmt_datetime(dt, locale=loc, format=format)  # type: ignore
            except Exception:  # pragma: no cover
                pass
        return dt.isoformat()

    def negotiate(self, accept_language_header: str) -> str:
        supported = self._available_locales()
        return parse_accept_language(accept_language_header or "", supported, self.cfg.default_locale)

    def missing_stats(self) -> Dict[str, int]:
        # For observability: returns {"ru:messages:key": count, ...}
        with self._lock:
            return {f"{loc}:{dom}:{k}": v for (loc, dom, k), v in self._missing.items()}

    # ------------------------ internals ------------------------

    def _available_locales(self) -> List[str]:
        root = self.cfg.base_path
        if not root.exists():
            return [self.cfg.default_locale]
        locales = [normalize_locale(p.name) for p in root.iterdir() if p.is_dir()]
        if not locales:
            locales = [self.cfg.default_locale]
        return locales

    def _domain_files(self, loc: str, domain: str) -> List[Path]:
        """Return best-match file list for locale chain, most specific first."""
        files: List[Path] = []
        for l in locale_chain(loc, self.cfg.default_locale):
            d = self.cfg.base_path / l
            if d.is_dir():
                for ext in (".json", ".yaml", ".yml"):
                    p = d / f"{domain}{ext}"
                    if p.exists():
                        files.append(p)
                        break
        return files

    def _load_catalog(self, loc: str, domain: str) -> _Catalog:
        files = self._domain_files(loc, domain)
        if not files:
            return _Catalog(data={}, mtime=0.0)
        merged: Dict[str, str] = {}
        latest_mtime = 0.0
        # most specific first, last wins -> we merge in reverse to let specific override fallback
        for path in reversed(files):
            merged.update(_load_file(path))
            latest_mtime = max(latest_mtime, path.stat().st_mtime)
        return _Catalog(data=merged, mtime=latest_mtime)

    def _get_catalog(self, loc: str, domain: str) -> _Catalog:
        key = (loc, domain)
        with self._lock:
            cat = self._catalogs.get(key)
            if cat is None:
                cat = self._load_catalog(loc, domain)
                self._catalogs[key] = cat
                return cat
            if self.cfg.auto_reload:
                # check mtimes; if any changed for chain, reload
                files = self._domain_files(loc, domain)
                current_mtime = max([0.0] + [p.stat().st_mtime for p in files])
                if current_mtime > cat.mtime:
                    cat = self._load_catalog(loc, domain)
                    self._catalogs[key] = cat
            return cat

    def _lookup(self, loc: str, domain: str, key: str, *, missing_silent: bool = False) -> str:
        # Search in domain, then fallback to default domain 'messages' if different
        cat = self._get_catalog(loc, domain)
        msg = cat.data.get(key)
        if msg is None and domain != "messages":
            msg = self._get_catalog(loc, "messages").data.get(key)
        if msg is None:
            if not missing_silent:
                self._record_missing(loc, domain, key)
            # last resort: return key (visible for debugging)
            return key
        return msg

    def _record_missing(self, loc: str, domain: str, key: str) -> None:
        with self._lock:
            self._missing[(loc, domain, key)] = self._missing.get((loc, domain, key), 0) + 1

    def _compile_if_needed(self, loc: str, domain: str, key: str, msg: str) -> _CompiledEntry:
        ckey = (loc, domain, key)
        now = time.time()
        with self._lock:
            entry = self._compiled.get(ckey)
            if entry and (now - entry.compiled_at) < self.cfg.cache_ttl_seconds:
                return entry
        # Compile outside lock (parsing can be modestly expensive)
        compiled = _compile_message(msg)
        with self._lock:
            self._compiled[ckey] = compiled
        return compiled

# ------------------------------- Convenience ------------------------------------------

# Singleton-like convenience factory (optional)
_default_i18n: Optional[I18n] = None

def init_i18n(base_path: str | Path, default_locale: str = "en", domains: Tuple[str, ...] = ("messages", "errors"), auto_reload: bool = False) -> I18n:
    global _default_i18n
    cfg = I18nConfig(base_path=Path(base_path), default_locale=default_locale, domains=domains, auto_reload=auto_reload)
    _default_i18n = I18n(cfg)
    _LOCALE_CTX.set(normalize_locale(default_locale))
    return _default_i18n

def get_i18n() -> I18n:
    if _default_i18n is None:
        raise RuntimeError("i18n is not initialized. Call init_i18n(base_path=...) first.")
    return _default_i18n

# ----------------------------- Example (docstring only) --------------------------------
"""
Usage example (FastAPI middleware/controller):

from mythos.localization.i18n import init_i18n, get_i18n
i18n = init_i18n(base_path="configs/locales", default_locale="en", auto_reload=True)

# Parse Accept-Language:
def detect_locale(request):
    accept = request.headers.get("Accept-Language","")
    loc = i18n.negotiate(accept)
    i18n.set_locale(loc)

# Translate:
text = i18n.t("greeting", name="Ivan")  # -> "Hello, Ivan!"
text = i18n.t("items", count=5)         # plural ICU message
text = i18n.tn("apple", "apples", 2)    # classic singular/plural fallback

# Context manager:
with i18n.use_locale("ru-RU"):
    i18n.t("greeting", name="Иван")

# Observability:
missing = i18n.missing_stats()  # {"ru:messages:unknown.key": 3, ...}
"""
