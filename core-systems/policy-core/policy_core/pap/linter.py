# policy_core/pap/linter.py
# Industrial-grade PAP policy linter — self-contained, stdlib-only (YAML optional).
# Features:
#  - File discovery with include globs and .policyignore (gitignore-like).
#  - Config resolution: CLI > policy-core.{json,yml,yaml} > pyproject.toml [tool.policy_core].
#  - Optional YAML via PyYAML if installed; otherwise JSON only.
#  - Built-in rules (POL001..POL012) + plugin loader (directory or dotted modules).
#  - Baseline support (create/update/use); stable fingerprinting.
#  - Content cache by file hash/mtime for speed.
#  - Parallel scanning with ThreadPoolExecutor.
#  - Reporters: text, json, SARIF 2.1.0 minimal.
#  - Severity thresholds & CI-friendly exit codes.
#  - Python 3.9+.

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import fnmatch
import hashlib
import io
import itertools
import json
import os
import pathlib
import queue
import re
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# -------- Optional YAML --------
YAML_AVAILABLE = False
try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False

# -------- Optional TOML (pyproject) --------
TOML_AVAILABLE = False
try:
    import tomllib  # Python 3.11+
    TOML_AVAILABLE = True
except Exception:
    try:
        import tomli as tomllib  # type: ignore
        TOML_AVAILABLE = True
    except Exception:
        TOML_AVAILABLE = False

VERSION = "1.2.0"

# -------------------- Severity & Finding --------------------

class Severity:
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    ORDER = {INFO: 0, WARNING: 1, ERROR: 2}

    @classmethod
    def valid(cls, s: str) -> bool:
        return s in cls.ORDER

    @classmethod
    def max(cls, a: str, b: str) -> str:
        return a if cls.ORDER[a] >= cls.ORDER[b] else b


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int = 1
    col: int = 1
    code: Optional[str] = None
    pointer: Optional[str] = None  # JSON Pointer-like path within document
    meta: Dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        base = f"{self.rule_id}|{self.severity}|{self.file}|{self.line}|{self.col}|{self.pointer or ''}|{self.message}"
        if self.code:
            base += f"|{self.code.strip()[:200]}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()


# -------------------- Config --------------------

DEFAULT_INCLUDE_GLOBS = [
    "**/*.policy.json",
    "**/*.policies.json",
    "**/*.policy.yaml",
    "**/*.policy.yml",
    "**/*.policies.yaml",
    "**/*.policies.yml",
]

DEFAULT_CONFIG = {
    "include": DEFAULT_INCLUDE_GLOBS,
    "exclude": [],
    "plugins": [],                   # ["pkg.module:Rules", "path/to/plugins"]
    "max_workers": 0,                # 0 => auto (min(32, os.cpu_count()+4))
    "severity_overrides": {},        # {"POL008": "error"}
    "enabled_rules": [],             # empty => all built-ins + plugins
    "disabled_rules": [],
    "format": "text",                # text|json|sarif
    "fail_on": "error",              # error|warning|info
    "severity_threshold": "info",    # ignore findings below this
    "cache": ".policy_core_cache.json",
    "baseline": None,                # "policy-baseline.json"
    "update_baseline": False,
    "actions_registry": [],          # ["iam.user.create", ...]
    "resources_registry": [],        # ["db:*", "s3://bucket/*", ...]
    "id_pattern": r"^[A-Z0-9_][A-Z0-9_\-:.]{2,}$",
    "action_pattern": r"^[a-z][a-z0-9_.:-]{2,}$",
    "resource_pattern": r"^[^\s]+$",  # no whitespace; allow wildcards
    "require_justification_on_wildcard": True,
    "now_utc_iso": None,            # override "now" when testing (ISO8601)
}

CONFIG_FILENAMES = [
    "policy-core.json",
    "policy-core.yaml",
    "policy-core.yml",
]

PYPROJECT_TABLE = ("tool", "policy_core")

# -------------------- Utilities --------------------

def debug(msg: str) -> None:
    if os.environ.get("POLICY_LINTER_DEBUG") == "1":
        sys.stderr.write(f"[debug] {msg}\n")

def load_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")

def compute_hash(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def utc_now_iso(override: Optional[str] = None) -> str:
    if override:
        return override
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_datetime_iso(s: str) -> Optional[datetime]:
    try:
        # naive support for Z
        if s.endswith("Z"):
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.fromisoformat(s)
    except Exception:
        return None

# -------------------- Ignore handling (.policyignore) --------------------

def load_ignore_patterns(root: pathlib.Path) -> List[str]:
    ignore_path = root / ".policyignore"
    patterns: List[str] = []
    if ignore_path.exists():
        for line in load_text(ignore_path).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    return patterns

def match_ignored(rel_path: str, patterns: List[str]) -> bool:
    # simple fnmatch matching for each pattern
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch("/" + rel_path, pat):
            return True
    return False

# -------------------- Config loading --------------------

def deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    res = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(res.get(k), dict):
            res[k] = deep_merge(res[k], v)  # type: ignore
        else:
            res[k] = v
    return res

def load_config(cwd: pathlib.Path, cli_overrides: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)

    # policy-core.{json,yaml,yml}
    for name in CONFIG_FILENAMES:
        p = cwd / name
        if p.exists():
            text = load_text(p)
            try:
                if p.suffix == ".json":
                    file_cfg = json.loads(text)
                else:
                    if not YAML_AVAILABLE:
                        raise RuntimeError("YAML config provided but PyYAML not installed")
                    file_cfg = yaml.safe_load(text) or {}
            except Exception as e:
                raise SystemExit(f"Error parsing config {p}: {e}")
            cfg = deep_merge(cfg, file_cfg)
            break

    # pyproject.toml
    pyproj = cwd / "pyproject.toml"
    if pyproj.exists() and TOML_AVAILABLE:
        try:
            with open(pyproj, "rb") as f:
                data = tomllib.load(f)
            node = data
            for part in PYPROJECT_TABLE:
                node = node.get(part, {})
            if node:
                cfg = deep_merge(cfg, node)
        except Exception as e:
            raise SystemExit(f"Error parsing pyproject.toml: {e}")

    # CLI overrides last
    cfg = deep_merge(cfg, {k: v for k, v in cli_overrides.items() if v is not None})

    # Validate basic fields
    if not Severity.valid(cfg["fail_on"]):
        raise SystemExit("fail_on must be one of info|warning|error")
    if not Severity.valid(cfg["severity_threshold"]):
        raise SystemExit("severity_threshold must be one of info|warning|error")
    if cfg["format"] not in ("text", "json", "sarif"):
        raise SystemExit("format must be one of text|json|sarif")

    return cfg

# -------------------- Discovery --------------------

def discover_files(root: pathlib.Path, includes: List[str], excludes: List[str], ignore_patterns: List[str]) -> List[pathlib.Path]:
    all_paths: List[pathlib.Path] = []
    for inc in includes:
        for p in root.glob(inc):
            if p.is_file():
                rel = str(p.relative_to(root)).replace("\\", "/")
                if match_ignored(rel, ignore_patterns):
                    continue
                excluded = any(fnmatch.fnmatch(rel, pat) for pat in excludes)
                if excluded:
                    continue
                all_paths.append(p)
    # de-dup
    result = sorted(set(all_paths))
    debug(f"Discovered {len(result)} files")
    return result

# -------------------- Parser --------------------

def parse_doc(path: pathlib.Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    text = load_text(path)
    ext = path.suffix.lower()
    try:
        if ext == ".json":
            return json.loads(text), "json"
        elif ext in (".yaml", ".yml") and YAML_AVAILABLE:
            return yaml.safe_load(text), "yaml"  # type: ignore
        elif ext in (".yaml", ".yml") and not YAML_AVAILABLE:
            raise RuntimeError("YAML file but PyYAML not installed")
        else:
            # fallback: try JSON
            return json.loads(text), "json"
    except Exception as e:
        raise ValueError(f"Parse error: {e}")

# -------------------- Rule API --------------------

class RuleContext:
    def __init__(self, config: Dict[str, Any], file: pathlib.Path, doc: Dict[str, Any]) -> None:
        self.config = config
        self.file = file
        self.doc = doc

class Rule:
    rule_id: str = "GEN000"
    description: str = "generic rule"
    default_severity: str = Severity.WARNING

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        return []

    # helper
    def sev(self, ctx: RuleContext) -> str:
        ov = ctx.config.get("severity_overrides", {})
        return ov.get(self.rule_id, self.default_severity)

# -------------------- Built-in Rules --------------------

def _iter_policies(doc: Dict[str, Any]) -> Iterable[Tuple[int, Dict[str, Any]]]:
    policies = doc.get("policies")
    if not isinstance(policies, list):
        return []
    for idx, pol in enumerate(policies):
        if isinstance(pol, dict):
            yield idx, pol

class POL001_TopLevelStructure(Rule):
    rule_id = "POL001"
    description = "Топ-уровень должен содержать 'version'(str) и 'policies'(list)."
    default_severity = Severity.ERROR

    def apply(self, ctx: RuleContext):
        doc = ctx.doc
        ok = True
        if "version" not in doc or not isinstance(doc.get("version"), (str, int)):
            ok = False
            yield Finding(self.rule_id, self.sev(ctx), "Отсутствует или некорректен 'version'.", str(ctx.file))
        if "policies" not in doc or not isinstance(doc.get("policies"), list):
            ok = False
            yield Finding(self.rule_id, self.sev(ctx), "Отсутствует или некорректен 'policies' (ожидается список).", str(ctx.file))
        if ok and len(doc.get("policies")) == 0:
            yield Finding(self.rule_id, Severity.WARNING, "Список 'policies' пуст.", str(ctx.file))

class POL002_UniquePolicyIds(Rule):
    rule_id = "POL002"
    description = "Идентификаторы политик должны быть уникальными и соответствовать шаблону."
    default_severity = Severity.ERROR

    def apply(self, ctx: RuleContext):
        seen = {}
        pat = re.compile(ctx.config.get("id_pattern", DEFAULT_CONFIG["id_pattern"]))
        for idx, pol in _iter_policies(ctx.doc):
            pid = pol.get("id")
            if not isinstance(pid, str) or not pat.match(pid):
                yield Finding(self.rule_id, self.sev(ctx), f"Некорректный id политики: {pid!r}.", str(ctx.file))
                continue
            if pid in seen:
                yield Finding(self.rule_id, self.sev(ctx), f"Дубликат id политики: {pid}.", str(ctx.file))
            seen[pid] = True

class POL003_EffectValidation(Rule):
    rule_id = "POL003"
    description = "effect должен быть 'allow' или 'deny'."
    default_severity = Severity.ERROR

    def apply(self, ctx: RuleContext):
        for idx, pol in _iter_policies(ctx.doc):
            eff = pol.get("effect")
            if eff not in ("allow", "deny"):
                yield Finding(self.rule_id, self.sev(ctx), f"Некорректный effect: {eff!r}.", str(ctx.file), pointer=f"/policies/{idx}/effect")

class POL004_ActionResourcePatterns(Rule):
    rule_id = "POL004"
    description = "Проверка форматов actions/resources."
    default_severity = Severity.ERROR

    def apply(self, ctx: RuleContext):
        act_pat = re.compile(ctx.config.get("action_pattern", DEFAULT_CONFIG["action_pattern"]))
        res_pat = re.compile(ctx.config.get("resource_pattern", DEFAULT_CONFIG["resource_pattern"]))
        for idx, pol in _iter_policies(ctx.doc):
            acts = pol.get("actions", [])
            if not isinstance(acts, list) or not acts:
                yield Finding(self.rule_id, self.sev(ctx), "Политика должна содержать непустой список 'actions'.", str(ctx.file), pointer=f"/policies/{idx}/actions")
            else:
                for a in acts:
                    if not isinstance(a, str) or not act_pat.match(a):
                        yield Finding(self.rule_id, self.sev(ctx), f"Некорректное имя действия: {a!r}.", str(ctx.file), pointer=f"/policies/{idx}/actions")

            res = pol.get("resources", [])
            if not isinstance(res, list) or not res:
                yield Finding(self.rule_id, self.sev(ctx), "Политика должна содержать непустой список 'resources'.", str(ctx.file), pointer=f"/policies/{idx}/resources")
            else:
                for r in res:
                    if not isinstance(r, str) or not res_pat.match(r):
                        yield Finding(self.rule_id, self.sev(ctx), f"Некорректный ресурс: {r!r}.", str(ctx.file), pointer=f"/policies/{idx}/resources")

class POL005_SubjectsAndConditions(Rule):
    rule_id = "POL005"
    description = "Проверка subjects и безопасной схемы conditions."
    default_severity = Severity.ERROR

    ALLOWED_COND_KEYS = {"allOf", "anyOf", "not", "equals", "in", "regex", "gt", "lt", "gte", "lte", "exists"}

    def _validate_cond(self, node: Any, path: str, file: str, sev: str) -> Iterable[Finding]:
        if isinstance(node, dict):
            for k, v in node.items():
                if k not in self.ALLOWED_COND_KEYS:
                    yield Finding(self.rule_id, sev, f"Недопустимый ключ в conditions: {k!r}.", file, pointer=path)
                else:
                    # structural checks
                    if k in ("allOf", "anyOf"):
                        if not isinstance(v, list) or not v:
                            yield Finding(self.rule_id, sev, f"{k} ожидает непустой список.", file, pointer=path + f"/{k}")
                        else:
                            for i, sub in enumerate(v):
                                yield from self._validate_cond(sub, path + f"/{k}/{i}", file, sev)
                    elif k == "not":
                        yield from self._validate_cond(v, path + "/not", file, sev)
                    elif k in ("equals", "in", "regex", "gt", "lt", "gte", "lte", "exists"):
                        # minimal sanity checks
                        if k == "in" and (not isinstance(v, list) or len(v) == 0):
                            yield Finding(self.rule_id, sev, "in ожидает непустой список.", file, pointer=path + "/in")
                        if k == "regex":
                            try:
                                re.compile(str(v))
                            except Exception as e:
                                yield Finding(self.rule_id, sev, f"Некорректный regex: {e}.", file, pointer=path + "/regex")
        else:
            yield Finding(self.rule_id, sev, "conditions должен быть объектом.", file, pointer=path)

    def apply(self, ctx: RuleContext):
        for idx, pol in _iter_policies(ctx.doc):
            # subjects
            subs = pol.get("subjects", [])
            if not isinstance(subs, list) or not subs:
                yield Finding(self.rule_id, self.sev(ctx), "Политика должна содержать непустой список 'subjects'.", str(ctx.file), pointer=f"/policies/{idx}/subjects")
            else:
                for s in subs:
                    if not isinstance(s, str) or not s.strip():
                        yield Finding(self.rule_id, self.sev(ctx), f"Некорректный subject: {s!r}.", str(ctx.file), pointer=f"/policies/{idx}/subjects")

            # conditions
            cond = pol.get("conditions")
            if cond is not None:
                yield from self._validate_cond(cond, f"/policies/{idx}/conditions", str(ctx.file), self.sev(ctx))

class POL006_RegistryReferences(Rule):
    rule_id = "POL006"
    description = "Ссылки на неизвестные actions/resources (если реестры заданы)."
    default_severity = Severity.ERROR

    def apply(self, ctx: RuleContext):
        acts_reg = set(ctx.config.get("actions_registry") or [])
        res_reg = set(ctx.config.get("resources_registry") or [])
        if not acts_reg and not res_reg:
            return
        for idx, pol in _iter_policies(ctx.doc):
            if acts_reg:
                for a in pol.get("actions", []) or []:
                    if a not in acts_reg:
                        yield Finding(self.rule_id, self.sev(ctx), f"Действие не в реестре: {a}.", str(ctx.file), pointer=f"/policies/{idx}/actions")
            if res_reg:
                for r in pol.get("resources", []) or []:
                    # простая проверка wildcard-совпадений из реестра с '*'
                    if not any(_wildcard_match(r, rr) for rr in res_reg):
                        yield Finding(self.rule_id, self.sev(ctx), f"Ресурс не в реестре: {r}.", str(ctx.file), pointer=f"/policies/{idx}/resources")

def _wildcard_match(value: str, pattern: str) -> bool:
    return fnmatch.fnmatch(value, pattern)

class POL007_Conflicts(Rule):
    rule_id = "POL007"
    description = "Конфликтующие политики (allow/deny) для одинаковых subjects/actions/resources."
    default_severity = Severity.WARNING

    def apply(self, ctx: RuleContext):
        # naive mapping key = (tuple(sorted(subs)), tuple(sorted(acts)), tuple(sorted(res)))
        buckets: Dict[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]], List[Tuple[str, int]]] = {}
        for idx, pol in _iter_policies(ctx.doc):
            subs = tuple(sorted([s for s in pol.get("subjects", []) if isinstance(s, str)]))
            acts = tuple(sorted([a for a in pol.get("actions", []) if isinstance(a, str)]))
            res = tuple(sorted([r for r in pol.get("resources", []) if isinstance(r, str)]))
            key = (subs, acts, res)
            eff = pol.get("effect")
            if subs and acts and res and eff in ("allow", "deny"):
                buckets.setdefault(key, []).append((eff, idx))
        for key, lst in buckets.items():
            effs = set(e for e, _ in lst)
            if len(effs) > 1:
                pairs = ", ".join([f"{e}@{i}" for e, i in lst])
                yield Finding(self.rule_id, self.sev(ctx), f"Найден конфликт allow/deny между политиками: {pairs}.", str(ctx.file))

class POL008_WildcardRequiresJustification(Rule):
    rule_id = "POL008"
    description = "Политики с resource='*' или action='*' требуют 'justification'."
    default_severity = Severity.ERROR

    def apply(self, ctx: RuleContext):
        if not ctx.config.get("require_justification_on_wildcard", True):
            return
        for idx, pol in _iter_policies(ctx.doc):
            acts = pol.get("actions") or []
            res = pol.get("resources") or []
            if any(a == "*" for a in acts) or any(r == "*" for r in res):
                just = pol.get("justification")
                if not isinstance(just, str) or len(just.strip()) < 10:
                    yield Finding(self.rule_id, self.sev(ctx), "Требуется 'justification' для wildcard-политики (>=10 символов).", str(ctx.file), pointer=f"/policies/{idx}")

class POL009_Expiry(Rule):
    rule_id = "POL009"
    description = "Истечение срока действия политики (поле 'expires', ISO 8601)."
    default_severity = Severity.WARNING

    def apply(self, ctx: RuleContext):
        now = parse_datetime_iso(utc_now_iso(ctx.config.get("now_utc_iso")))
        assert now is not None
        for idx, pol in _iter_policies(ctx.doc):
            exp = pol.get("expires")
            if exp:
                dt = parse_datetime_iso(str(exp))
                if not dt:
                    yield Finding(self.rule_id, Severity.ERROR, f"Некорректный формат 'expires': {exp}.", str(ctx.file), pointer=f"/policies/{idx}/expires")
                elif dt < now:
                    yield Finding(self.rule_id, self.sev(ctx), f"Срок действия политики истёк: {exp}.", str(ctx.file), pointer=f"/policies/{idx}/expires")

class POL010_RedundantNeverMatches(Rule):
    rule_id = "POL010"
    description = "Бесполезные/невыполнимые условия (например, in: [])."
    default_severity = Severity.WARNING

    def _check_impossible(self, node: Any) -> bool:
        # simplistic detection of some impossible conditions
        if isinstance(node, dict):
            if "in" in node:
                v = node["in"]
                if isinstance(v, list) and len(v) == 0:
                    return True
            # recurse
            for k in ("allOf", "anyOf"):
                if k in node and isinstance(node[k], list):
                    if k == "allOf" and any(self._check_impossible(x) for x in node[k]):
                        return True
                    if k == "anyOf" and all(self._check_impossible(x) for x in node[k]):
                        return True
            if "not" in node:
                # if not of impossible is always true — treat as okay
                return False
        return False

    def apply(self, ctx: RuleContext):
        for idx, pol in _iter_policies(ctx.doc):
            cond = pol.get("conditions")
            if cond and self._check_impossible(cond):
                yield Finding(self.rule_id, self.sev(ctx), "Условия политики невыполнимы (например, in: []).", str(ctx.file), pointer=f"/policies/{idx}/conditions")

class POL011_NameConventions(Rule):
    rule_id = "POL011"
    description = "Рекомендованные соглашения об именовании id (UPPER_CASE, '-', ':', '.')."
    default_severity = Severity.INFO

    def apply(self, ctx: RuleContext):
        pat = re.compile(ctx.config.get("id_pattern", DEFAULT_CONFIG["id_pattern"]))
        for idx, pol in _iter_policies(ctx.doc):
            pid = pol.get("id")
            if isinstance(pid, str) and not pat.match(pid):
                yield Finding(self.rule_id, self.sev(ctx), f"id не соответствует рекомендуемому шаблону: {pid}.", str(ctx.file), pointer=f"/policies/{idx}/id")

class POL012_JustificationOnDenySensitive(Rule):
    rule_id = "POL012"
    description = "Для effect='deny' желателен 'justification' (аудит)."
    default_severity = Severity.INFO

    def apply(self, ctx: RuleContext):
        for idx, pol in _iter_policies(ctx.doc):
            if pol.get("effect") == "deny":
                just = pol.get("justification")
                if not just or len(str(just).strip()) < 5:
                    yield Finding(self.rule_id, self.sev(ctx), "Для deny рекомендуется 'justification' (>=5 символов).", str(ctx.file), pointer=f"/policies/{idx}/justification")

BUILTIN_RULES: List[Rule] = [
    POL001_TopLevelStructure(),
    POL002_UniquePolicyIds(),
    POL003_EffectValidation(),
    POL004_ActionResourcePatterns(),
    POL005_SubjectsAndConditions(),
    POL006_RegistryReferences(),
    POL007_Conflicts(),
    POL008_WildcardRequiresJustification(),
    POL009_Expiry(),
    POL010_RedundantNeverMatches(),
    POL011_NameConventions(),
    POL012_JustificationOnDenySensitive(),
]

# -------------------- Plugin Loader --------------------

def load_plugins(specs: List[str]) -> List[Rule]:
    rules: List[Rule] = []
    for spec in specs or []:
        p = pathlib.Path(spec)
        if p.exists():
            # load all *.py files under directory as modules
            for mod_path in p.rglob("*.py"):
                try:
                    ns: Dict[str, Any] = {}
                    exec(mod_path.read_text(encoding="utf-8"), ns, ns)
                    for obj in ns.values():
                        if isinstance(obj, type) and issubclass(obj, Rule) and obj is not Rule:
                            rules.append(obj())
                except Exception as e:
                    sys.stderr.write(f"Plugin load error from {mod_path}: {e}\n")
        else:
            # dotted import: module[:symbol]
            if ":" in spec:
                mod_name, sym = spec.split(":", 1)
            else:
                mod_name, sym = spec, None
            try:
                module = __import__(mod_name, fromlist=["*"])
                if sym:
                    candidate = getattr(module, sym)
                    if isinstance(candidate, (list, tuple)):
                        for c in candidate:
                            if isinstance(c, type) and issubclass(c, Rule) and c is not Rule:
                                rules.append(c())
                    elif isinstance(candidate, type) and issubclass(candidate, Rule):
                        rules.append(candidate())
                else:
                    for name in dir(module):
                        obj = getattr(module, name)
                        if isinstance(obj, type) and issubclass(obj, Rule) and obj is not Rule:
                            rules.append(obj())
            except Exception as e:
                sys.stderr.write(f"Plugin import error '{spec}': {e}\n")
    return rules

# -------------------- Cache --------------------

def load_cache(path: pathlib.Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(load_text(path))
    except Exception:
        return {}

def save_cache(path: pathlib.Path, data: Dict[str, Any]) -> None:
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        sys.stderr.write(f"Cache save error: {e}\n")

# -------------------- Baseline --------------------

def load_baseline(path: Optional[pathlib.Path]) -> Dict[str, Any]:
    if not path or not path.exists():
        return {"fingerprints": set()}
    try:
        data = json.loads(load_text(path))
        fps = set(data.get("fingerprints", []))
        return {"fingerprints": fps}
    except Exception:
        return {"fingerprints": set()}

def save_baseline(path: pathlib.Path, fingerprints: Iterable[str]) -> None:
    doc = {"version": VERSION, "generated_at": utc_now_iso(None), "fingerprints": sorted(set(fingerprints))}
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

# -------------------- Lint Engine --------------------

class LintEngine:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.rules = self._build_rules(config)

    def _build_rules(self, config: Dict[str, Any]) -> List[Rule]:
        rules = list(BUILTIN_RULES)
        rules += load_plugins(config.get("plugins") or [])
        # enable/disable
        en = set(config.get("enabled_rules") or [])
        dis = set(config.get("disabled_rules") or [])
        if en:
            rules = [r for r in rules if r.rule_id in en]
        if dis:
            rules = [r for r in rules if r.rule_id not in dis]
        # sort by rule_id for stable ordering
        rules.sort(key=lambda r: r.rule_id)
        return rules

    def lint_file(self, file: pathlib.Path) -> Tuple[List[Finding], Optional[str]]:
        try:
            doc, fmt = parse_doc(file)
        except Exception as e:
            return [Finding("PARSE", Severity.ERROR, str(e), str(file))], None
        if not isinstance(doc, dict):
            return [Finding("FORMAT", Severity.ERROR, "Документ должен быть объектом.", str(file))], None
        ctx = RuleContext(self.config, file, doc)
        findings: List[Finding] = []
        for rule in self.rules:
            try:
                findings.extend(list(rule.apply(ctx)))
            except Exception as e:
                tb = traceback.format_exc(limit=1)
                findings.append(Finding("ENGINE", Severity.ERROR, f"Ошибка при выполнении {rule.rule_id}: {e}", str(file), meta={"trace": tb}))
        return findings, fmt

# -------------------- Reporting --------------------

def filter_by_severity(findings: List[Finding], threshold: str) -> List[Finding]:
    return [f for f in findings if Severity.ORDER[f.severity] >= Severity.ORDER[threshold]]

def render_text(findings_by_file: Dict[str, List[Finding]]) -> str:
    out = io.StringIO()
    total = sum(len(v) for v in findings_by_file.values())
    worst = Severity.INFO
    for v in findings_by_file.values():
        for f in v:
            worst = Severity.max(worst, f.severity)
    out.write(f"policy-core linter v{VERSION} — findings: {total}, worst: {worst}\n")
    for file, fnds in sorted(findings_by_file.items()):
        out.write(f"\n{file}\n")
        out.write("-" * len(file) + "\n")
        for f in fnds:
            loc = f"{f.line}:{f.col}"
            ptr = f" {f.pointer}" if f.pointer else ""
            out.write(f"[{f.severity.upper()}] {f.rule_id} {loc}{ptr} — {f.message}\n")
    return out.getvalue()

def render_json(findings_by_file: Dict[str, List[Finding]]) -> str:
    payload = {
        "version": VERSION,
        "generated_at": utc_now_iso(None),
        "files": {
            file: [dataclasses.asdict(f) | {"fingerprint": f.fingerprint()} for f in fnds]
            for file, fnds in findings_by_file.items()
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)

def render_sarif(findings_by_file: Dict[str, List[Finding]]) -> str:
    # Minimal SARIF 2.1.0
    rules_meta: Dict[str, Dict[str, Any]] = {}
    runs_results: List[Dict[str, Any]] = []

    for file, fnds in findings_by_file.items():
        for f in fnds:
            rules_meta.setdefault(f.rule_id, {"id": f.rule_id, "name": f.rule_id, "shortDescription": {"text": f.rule_id}, "fullDescription": {"text": f.message}})
            runs_results.append({
                "ruleId": f.rule_id,
                "level": {"info": "note", "warning": "warning", "error": "error"}[f.severity],
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file.replace("\\", "/")},
                        "region": {"startLine": f.line or 1, "startColumn": f.col or 1}
                    }
                }]
            })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "policy-core linter",
                    "informationUri": "https://example.invalid/policy-core",
                    "version": VERSION,
                    "rules": list(rules_meta.values()),
                }
            },
            "results": runs_results
        }]
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)

# -------------------- Orchestrate --------------------

def decide_exit_code(findings: List[Finding], fail_on: str) -> int:
    worst = Severity.INFO
    for f in findings:
        worst = Severity.max(worst, f.severity)
    return 1 if Severity.ORDER[worst] >= Severity.ORDER[fail_on] and findings else 0

def worker_task(args: Tuple[pathlib.Path, Dict[str, Any], Dict[str, Any]]) -> Tuple[str, List[Finding], Optional[str], str]:
    file, cfg, cache_entry = args
    engine = LintEngine(cfg)
    # caching
    file_hash = compute_hash(file)
    if cache_entry and cache_entry.get("hash") == file_hash and cache_entry.get("fmt") in ("json", "yaml"):
        # reuse previous findings
        cached = cache_entry.get("findings", [])
        findings = []
        for c in cached:
            try:
                findings.append(Finding(**c))
            except Exception:
                pass
        return str(file), findings, cache_entry.get("fmt"), file_hash
    # fresh
    findings, fmt = engine.lint_file(file)
    return str(file), findings, fmt, file_hash

def run_lint(paths: List[pathlib.Path], cfg: Dict[str, Any], root: pathlib.Path) -> Tuple[Dict[str, List[Finding]], List[Finding]]:
    cache_path = root / (cfg.get("cache") or ".policy_core_cache.json")
    cache = load_cache(cache_path)

    # previous per-file cache
    per_file_cache: Dict[str, Any] = cache.get("files", {})

    max_workers = int(cfg.get("max_workers") or 0) or min(32, (os.cpu_count() or 4) + 4)

    tasks: List[Tuple[pathlib.Path, Dict[str, Any], Dict[str, Any]]] = []
    for p in paths:
        tasks.append((p, cfg, per_file_cache.get(str(p), {})))

    results: Dict[str, List[Finding]] = {}
    all_findings: List[Finding] = []
    new_cache_files: Dict[str, Any] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for file, findings, fmt, file_hash in ex.map(worker_task, tasks):
            # severity threshold
            filtered = filter_by_severity(findings, cfg["severity_threshold"])
            results[file] = filtered
            all_findings.extend(filtered)
            new_cache_files[file] = {
                "hash": file_hash,
                "fmt": fmt,
                "findings": [dataclasses.asdict(f) for f in filtered],
            }

    # Baseline
    bl_path = pathlib.Path(cfg["baseline"]) if cfg.get("baseline") else None
    baseline = load_baseline(bl_path)
    fps_bl = baseline["fingerprints"]

    if bl_path and cfg.get("update_baseline"):
        # update baseline to include all current findings
        save_baseline(bl_path, (f.fingerprint() for f in all_findings))
    elif bl_path:
        # filter out baseline findings
        results = {
            file: [f for f in lst if f.fingerprint() not in fps_bl]
            for file, lst in results.items()
        }
        all_findings = [f for f in all_findings if f.fingerprint() not in fps_bl]

    # Save cache
    cache_doc = {
        "version": VERSION,
        "generated_at": utc_now_iso(None),
        "files": new_cache_files,
    }
    save_cache(cache_path, cache_doc)

    return results, all_findings

# -------------------- CLI --------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="policy-linter", description="policy-core PAP linter")
    ap.add_argument("path", nargs="?", default=".", help="Путь до корня проекта или файла.")
    ap.add_argument("--format", choices=["text", "json", "sarif"], help="Формат отчёта.")
    ap.add_argument("--fail-on", choices=[Severity.INFO, Severity.WARNING, Severity.ERROR], help="Порог сбоя по наихудшей серьёзности.")
    ap.add_argument("--severity-threshold", choices=[Severity.INFO, Severity.WARNING, Severity.ERROR], help="Минимальная серьёзность для отчёта.")
    ap.add_argument("--include", action="append", help="Glob-инклюды (можно несколько).")
    ap.add_argument("--exclude", action="append", help="Glob-исключения (можно несколько).")
    ap.add_argument("--plugins", action="append", help="Плагины: путь к каталогу или dotted module[:symbol].")
    ap.add_argument("--baseline", help="Путь к baseline JSON.")
    ap.add_argument("--update-baseline", action="store_true", help="Обновить baseline текущими findings.")
    ap.add_argument("--max-workers", type=int, help="Количество потоков.")
    ap.add_argument("--cache", help="Файл кэша.")
    ap.add_argument("--actions-registry", help="JSON-файл с разрешёнными actions.")
    ap.add_argument("--resources-registry", help="JSON-файл с разрешёнными resources (поддерживается wildcard).")
    ap.add_argument("--print-config", action="store_true", help="Показать итоговую конфигурацию и выйти.")
    ap.add_argument("--version", action="store_true", help="Показать версию и выйти.")
    args = ap.parse_args(argv)

    if args.version:
        print(f"policy-core linter v{VERSION}")
        return 0

    root = pathlib.Path(args.path).resolve()
    if root.is_file():
        cwd = root.parent
    else:
        cwd = root

    # CLI overrides
    cli_overrides: Dict[str, Any] = {
        "format": args.format,
        "fail_on": args.fail_on,
        "severity_threshold": args.severity_threshold,
        "baseline": args.baseline,
        "update_baseline": args.update_baseline,
        "max_workers": args.max_workers,
        "cache": args.cache,
    }
    if args.include:
        cli_overrides["include"] = args.include
    if args.exclude:
        cli_overrides["exclude"] = args.exclude
    if args.plugins:
        cli_overrides["plugins"] = args.plugins

    cfg = load_config(cwd, cli_overrides)

    # optional registries
    if args.actions_registry:
        try:
            cfg["actions_registry"] = json.loads(pathlib.Path(args.actions_registry).read_text(encoding="utf-8"))
        except Exception as e:
            raise SystemExit(f"Не удалось прочитать actions-registry: {e}")
    if args.resources_registry:
        try:
            cfg["resources_registry"] = json.loads(pathlib.Path(args.resources_registry).read_text(encoding="utf-8"))
        except Exception as e:
            raise SystemExit(f"Не удалось прочитать resources-registry: {e}")

    if args.print_config:
        print(json.dumps(cfg, ensure_ascii=False, indent=2))
        return 0

    # Discovery
    root_scan = root if root.is_dir() else root.parent
    ignore_pats = load_ignore_patterns(root_scan)
    includes = cfg.get("include") or DEFAULT_INCLUDE_GLOBS
    excludes = cfg.get("exclude") or []
    files: List[pathlib.Path]
    if root.is_file():
        files = [root]
    else:
        files = discover_files(root_scan, includes, excludes, ignore_pats)
    if not files:
        print("Файлы политик не найдены.", file=sys.stderr)
        return 0

    # Lint
    findings_by_file, all_findings = run_lint(files, cfg, root_scan)

    # Report
    if cfg["format"] == "text":
        out = render_text(findings_by_file)
    elif cfg["format"] == "json":
        out = render_json(findings_by_file)
    else:
        out = render_sarif(findings_by_file)

    print(out)
    return decide_exit_code(list(itertools.chain.from_iterable(findings_by_file.values())), cfg["fail_on"])


if __name__ == "__main__":
    sys.exit(main())
