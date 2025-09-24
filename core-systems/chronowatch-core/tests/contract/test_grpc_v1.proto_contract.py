# chronowatch-core/tests/contract/test_grpc_v1.proto_contract.py
# Industrial gRPC v1 proto contract test (pytest)
# - Pure stdlib: re, json, hashlib, dataclasses, pathlib, typing
# - Parses .proto, validates style/versioning, checks additive-only compatibility
# - Compares against JSON snapshot if present; allows regeneration via env
#
# ENV:
#   REGENERATE_CONTRACT=1   -> write/overwrite snapshot JSON from current .proto
#
# Snapshot location (relative to this file):
#   chronowatch-core/tests/contract/_snapshots/grpc_v1_contract.json
#
# Assumptions:
#   - The project contains exactly one primary v1 .proto for ChronoWatch gRPC API,
#     or a clearly identifiable one by name/patterns. If multiple candidates found,
#     the test will fail with a precise list to disambiguate.

from __future__ import annotations

import json
import os
import re
import hashlib
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# -------------------------------
# Utilities
# -------------------------------

THIS_FILE = Path(__file__).resolve()
TEST_DIR = THIS_FILE.parent
PROJECT_ROOT = next(
    (p for p in THIS_FILE.parents if (p / ".git").exists() or (p / "proto").exists()),
    TEST_DIR.parent.parent,  # fallback two levels up
)
SNAPSHOT_DIR = TEST_DIR / "_snapshots"
SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
SNAPSHOT_PATH = SNAPSHOT_DIR / "grpc_v1_contract.json"

PROTO_GLOBS = [
    "**/proto/**/v1/*.proto",
    "**/proto/**/*v1*.proto",
    "**/*chronowatch*/*v1*.proto",
    "**/*chronowatch*/*.proto",
    "**/proto/**/*.proto",
]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _strip_comments(src: str) -> str:
    # Remove block comments
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    # Remove line comments
    src = re.sub(r"//.*?$", "", src, flags=re.M)
    return src


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# -------------------------------
# Data structures
# -------------------------------

@dataclass
class FieldSpec:
    number: int
    name: str
    ftype: str
    label: Optional[str] = None  # optional|repeated|None
    options: Dict[str, str] = dc_field(default_factory=dict)


@dataclass
class MessageSpec:
    name: str
    fields: Dict[int, FieldSpec] = dc_field(default_factory=dict)  # keyed by number
    reserved_numbers: List[Tuple[int, int]] = dc_field(default_factory=list)  # ranges inclusive
    reserved_names: List[str] = dc_field(default_factory=list)


@dataclass
class RpcSpec:
    name: str
    request_type: str
    response_type: str
    client_streaming: bool = False
    server_streaming: bool = False


@dataclass
class ServiceSpec:
    name: str
    rpcs: Dict[str, RpcSpec] = dc_field(default_factory=dict)


@dataclass
class ProtoSpec:
    syntax: str
    package: str
    options: Dict[str, str]
    messages: Dict[str, MessageSpec]
    services: Dict[str, ServiceSpec]

    def to_canonical(self) -> Dict:
        # Canonical, stable ordering for hashing/comparison
        return {
            "syntax": self.syntax,
            "package": self.package,
            "options": dict(sorted(self.options.items())),
            "messages": {
                mname: {
                    "fields": {
                        str(num): {
                            "name": f.name,
                            "type": f.ftype,
                            "label": f.label,
                            "options": dict(sorted(f.options.items())),
                        }
                        for num, f in sorted(ms.fields.items(), key=lambda x: x[0])
                    },
                    "reserved_numbers": [
                        [lo, hi] for (lo, hi) in sorted(ms.reserved_numbers)
                    ],
                    "reserved_names": sorted(ms.reserved_names),
                }
                for mname, ms in sorted(self.messages.items())
            },
            "services": {
                sname: {
                    "rpcs": {
                        rname: {
                            "request_type": r.request_type,
                            "response_type": r.response_type,
                            "client_streaming": r.client_streaming,
                            "server_streaming": r.server_streaming,
                        }
                        for rname, r in sorted(s.rpcs.items())
                    }
                }
                for sname, s in sorted(self.services.items())
            },
        }


# -------------------------------
# Proto parser (minimal, robust for typical .proto)
# -------------------------------

class ProtoParser:
    def __init__(self, text: str):
        self.original = text
        self.src = _strip_comments(text)

    def parse(self) -> ProtoSpec:
        syntax = self._parse_syntax()
        package = self._parse_package()
        options = self._parse_options()

        messages = self._parse_messages()
        services = self._parse_services()

        return ProtoSpec(
            syntax=syntax,
            package=package,
            options=options,
            messages=messages,
            services=services,
        )

    def _parse_syntax(self) -> str:
        m = re.search(r'\bsyntax\s*=\s*"([^"]+)"\s*;', self.src)
        return m.group(1).strip() if m else ""

    def _parse_package(self) -> str:
        m = re.search(r'\bpackage\s+([a-zA-Z0-9_.]+)\s*;', self.src)
        return m.group(1).strip() if m else ""

    def _parse_options(self) -> Dict[str, str]:
        opts = {}
        for m in re.finditer(r'\boption\s+([a-zA-Z0-9_.]+)\s*=\s*([^;]+);', self.src):
            key = m.group(1).strip()
            val = m.group(2).strip()
            opts[key] = val
        return opts

    def _extract_blocks(self, kind: str) -> List[Tuple[str, str]]:
        # Returns list of (Name, block_content_inside_braces)
        # E.g. kind="message" or "service"
        pattern = re.compile(rf'\b{kind}\s+([A-Za-z0-9_]+)\s*\{{', re.M)
        blocks: List[Tuple[str, str]] = []
        for m in pattern.finditer(self.src):
            name = m.group(1)
            start = m.end() - 1  # position of '{'
            end = self._find_matching_brace(self.src, start)
            if end == -1:
                continue
            content = self.src[start + 1 : end]
            blocks.append((name, content))
        return blocks

    @staticmethod
    def _find_matching_brace(s: str, start_brace_idx: int) -> int:
        depth = 0
        for i in range(start_brace_idx, len(s)):
            c = s[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i
        return -1

    def _parse_messages(self) -> Dict[str, MessageSpec]:
        messages: Dict[str, MessageSpec] = {}
        for name, content in self._extract_blocks("message"):
            ms = MessageSpec(name=name)
            ms.reserved_numbers, ms.reserved_names = self._parse_reserved(content)

            # Parse fields at top level of the message content (ignore nested)
            ms.fields = self._parse_fields_top_level(content)
            messages[name] = ms
        return messages

    def _parse_reserved(self, content: str) -> Tuple[List[Tuple[int, int]], List[str]]:
        num_ranges: List[Tuple[int, int]] = []
        names: List[str] = []
        for m in re.finditer(r'\breserved\s+([^;]+);', content):
            blob = m.group(1)
            # numbers/ranges and/or names in quotes may be mixed, e.g.:
            # reserved 1, 2 to 5, "old_name";
            tokens = [t.strip() for t in blob.split(",")]
            for t in tokens:
                if not t:
                    continue
                if t.startswith('"') and t.endswith('"'):
                    names.append(t.strip('"'))
                elif "to" in t:
                    lo_s, hi_s = [x.strip() for x in t.split("to", 1)]
                    if lo_s.isdigit() and hi_s.isdigit():
                        num_ranges.append((int(lo_s), int(hi_s)))
                else:
                    if t.isdigit():
                        n = int(t)
                        num_ranges.append((n, n))
        return num_ranges, names

    def _parse_fields_top_level(self, content: str) -> Dict[int, FieldSpec]:
        fields: Dict[int, FieldSpec] = {}
        depth = 0
        # process line by line, but track braces to ignore nested blocks
        for line in content.splitlines():
            # quick brace depth tracking
            depth += line.count("{")
            if depth > 0 and "}" in line:
                # Handle cases like "};" on same line
                pass

            if depth == 0:
                m = re.search(
                    r'^\s*(?:(repeated|optional)\s+)?([.\w]+)\s+(\w+)\s*=\s*(\d+)\s*(\[(.*?)\])?\s*;',
                    line,
                )
                if m:
                    label = m.group(1)
                    ftype = m.group(2)
                    name = m.group(3)
                    num = int(m.group(4))
                    opts_blob = m.group(6) or ""
                    options = self._parse_field_options(opts_blob)
                    fields[num] = FieldSpec(
                        number=num, name=name, ftype=ftype, label=label, options=options
                    )

            depth -= line.count("}")
        return fields

    @staticmethod
    def _parse_field_options(blob: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        # key = value, comma-separated
        for m in re.finditer(r'([a-zA-Z0-9_.]+)\s*=\s*("[^"]*"|[^,\s]+)', blob):
            k = m.group(1).strip()
            v = m.group(2).strip()
            out[k] = v
        return out

    def _parse_services(self) -> Dict[str, ServiceSpec]:
        services: Dict[str, ServiceSpec] = {}
        for name, content in self._extract_blocks("service"):
            svc = ServiceSpec(name=name, rpcs={})
            # Parse RPC signatures at top level
            depth = 0
            for line in content.splitlines():
                depth += line.count("{")
                if depth == 0:
                    m = re.search(
                        r'^\s*rpc\s+(\w+)\s*\(\s*(stream\s+)?([.\w]+)\s*\)\s*returns\s*\(\s*(stream\s+)?([.\w]+)\s*\)\s*;',
                        line,
                    )
                    if m:
                        rpc_name = m.group(1)
                        cs = bool(m.group(2))
                        req = m.group(3)
                        ss = bool(m.group(4))
                        res = m.group(5)
                        svc.rpcs[rpc_name] = RpcSpec(
                            name=rpc_name,
                            request_type=req,
                            response_type=res,
                            client_streaming=cs,
                            server_streaming=ss,
                        )
                depth -= line.count("}")
            services[name] = svc
        return services


# -------------------------------
# Contract discovery
# -------------------------------

def discover_proto_file() -> Path:
    candidates: List[Path] = []
    for glob in PROTO_GLOBS:
        candidates.extend(PROJECT_ROOT.glob(glob))
    # Filter unique and existing
    uniq = sorted({p.resolve() for p in candidates if p.is_file()})

    if not uniq:
        raise AssertionError(
            f"No .proto files found under {PROJECT_ROOT}. "
            f"Looked with patterns: {PROTO_GLOBS}"
        )

    # Heuristics to pick v1 chronowatch proto
    def score(p: Path) -> int:
        s = p.as_posix().lower()
        sc = 0
        if "/v1/" in s:
            sc += 10
        if "v1" in p.name.lower():
            sc += 5
        if "chronowatch" in s:
            sc += 4
        if "/proto/" in s:
            sc += 2
        if s.endswith(".proto"):
            sc += 1
        return sc

    best = max(uniq, key=score)
    # If ambiguity exists (multiple with same top score), force explicit resolution
    top_score = score(best)
    same = [p for p in uniq if score(p) == top_score]
    if len(same) > 1:
        msg = "Ambiguous .proto candidates:\n" + "\n".join(f"- {p}" for p in same)
        raise AssertionError(msg)

    return best


# -------------------------------
# Style / naming checks
# -------------------------------

SNAKE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
PASCAL_RE = re.compile(r"^[A-Z][A-Za-z0-9]*$")
SERVICE_SUFFIX = "Service"


def validate_style(spec: ProtoSpec) -> List[str]:
    errors: List[str] = []

    if spec.syntax != "proto3":
        errors.append(f"syntax must be 'proto3' (got '{spec.syntax}')")

    if "v1" not in spec.package:
        errors.append(f"package must contain version segment 'v1' (got '{spec.package}')")

    # Service and RPC naming
    for s_name, svc in spec.services.items():
        if not PASCAL_RE.match(s_name):
            errors.append(f"service '{s_name}': must be PascalCase")
        if not s_name.endswith(SERVICE_SUFFIX):
            errors.append(f"service '{s_name}': name must end with '{SERVICE_SUFFIX}'")
        for r_name, _ in svc.rpcs.items():
            if not PASCAL_RE.match(r_name):
                errors.append(f"rpc '{s_name}.{r_name}': must be PascalCase")

    # Message and field naming
    for m_name, msg in spec.messages.items():
        if not PASCAL_RE.match(m_name):
            errors.append(f"message '{m_name}': must be PascalCase")
        seen_names: set = set()
        for num, f in msg.fields.items():
            if not SNAKE_RE.match(f.name):
                errors.append(f"field '{m_name}.{f.name}': must be snake_case")
            if f.name in seen_names:
                errors.append(f"message '{m_name}': duplicate field name '{f.name}'")
            seen_names.add(f.name)
            if num < 1 or num > 536870911:
                errors.append(f"field '{m_name}.{f.name}': tag {num} out of range")
        # No overlapping reserved number ranges
        merged: List[Tuple[int, int]] = []
        for lo, hi in sorted(msg.reserved_numbers):
            if merged and lo <= merged[-1][1]:
                errors.append(f"message '{m_name}': overlapping reserved ranges")
            merged.append((lo, hi))

    return errors


# -------------------------------
# Compatibility checks (additive-only)
# -------------------------------

def load_snapshot() -> Optional[Dict]:
    if SNAPSHOT_PATH.exists():
        return json.loads(_read_text(SNAPSHOT_PATH))
    return None


def save_snapshot(spec: ProtoSpec) -> None:
    data = spec.to_canonical()
    SNAPSHOT_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def diff_dict(old: Dict, new: Dict, path: str = "") -> List[str]:
    # Minimal recursive diff with human-friendly paths
    diffs: List[str] = []
    old_keys = set(old.keys())
    new_keys = set(new.keys())
    for k in sorted(old_keys - new_keys):
        diffs.append(f"- removed {path}.{k}")
    for k in sorted(new_keys - old_keys):
        diffs.append(f"+ added   {path}.{k}")
    for k in sorted(old_keys & new_keys):
        ov = old[k]
        nv = new[k]
        p = f"{path}.{k}" if path else k
        if isinstance(ov, dict) and isinstance(nv, dict):
            diffs.extend(diff_dict(ov, nv, p))
        else:
            if ov != nv:
                diffs.append(f"* changed {p}: {ov!r} -> {nv!r}")
    return diffs


def _range_contains(ranges: List[List[int]], n: int) -> bool:
    for lo, hi in ranges:
        if lo <= n <= hi:
            return True
    return False


def check_backward_compatibility(old: Dict, new: Dict) -> List[str]:
    """
    Enforce additive-only rules:
    - package and syntax must be identical
    - services in old must exist in new, with all RPCs identical
    - messages in old must exist in new
    - fields in old messages must exist in new with the same number, type, label
      (if a field is removed in new, its tag number must be reserved in new)
    - reserved numbers in old must still be reserved or unused in new
    """
    errors: List[str] = []

    if old.get("syntax") != new.get("syntax"):
        errors.append(f"syntax change: {old.get('syntax')} -> {new.get('syntax')}")
    if old.get("package") != new.get("package"):
        errors.append(f"package change: {old.get('package')} -> {new.get('package')}")

    # Services
    old_svcs = old.get("services", {})
    new_svcs = new.get("services", {})
    for sname, s_old in old_svcs.items():
        s_new = new_svcs.get(sname)
        if not s_new:
            errors.append(f"service removed: {sname}")
            continue
        old_rpcs = s_old.get("rpcs", {})
        new_rpcs = s_new.get("rpcs", {})
        for rname, r_old in old_rpcs.items():
            r_new = new_rpcs.get(rname)
            if not r_new:
                errors.append(f"rpc removed: {sname}.{rname}")
                continue
            for key in ["request_type", "response_type", "client_streaming", "server_streaming"]:
                if r_old.get(key) != r_new.get(key):
                    errors.append(f"rpc signature changed: {sname}.{rname}.{key}: {r_old.get(key)} -> {r_new.get(key)}")

    # Messages and fields
    old_msgs = old.get("messages", {})
    new_msgs = new.get("messages", {})
    for mname, m_old in old_msgs.items():
        m_new = new_msgs.get(mname)
        if not m_new:
            errors.append(f"message removed: {mname}")
            continue

        old_fields = m_old.get("fields", {})
        new_fields = m_new.get("fields", {})
        new_reserved = m_new.get("reserved_numbers", [])

        # Check existing fields unchanged; if removed, must be reserved
        for num_str, f_old in old_fields.items():
            f_new = new_fields.get(num_str)
            num = int(num_str)
            if not f_new:
                if not _range_contains(new_reserved, num):
                    errors.append(
                        f"field removed without reserving tag: {mname} tag={num} name={f_old.get('name')}"
                    )
                continue
            # compare stable attributes
            for key in ["name", "type", "label"]:
                if f_old.get(key) != f_new.get(key):
                    errors.append(
                        f"field changed: {mname} tag={num} {key}: {f_old.get(key)} -> {f_new.get(key)}"
                    )

        # Check reserved numbers from old still reserved or unused
        old_reserved = m_old.get("reserved_numbers", [])
        for lo, hi in old_reserved:
            for n in range(int(lo), int(hi) + 1):
                # if now used by any field, it's a break
                if str(n) in new_fields:
                    errors.append(
                        f"reserved tag reused: {mname} tag={n} previously reserved {lo}-{hi}"
                    )

    return errors


# -------------------------------
# Tests
# -------------------------------

def test_grpc_v1_proto_contract():
    # Discover and parse proto
    proto_path = discover_proto_file()
    text = _read_text(proto_path)
    parser = ProtoParser(text)
    spec = parser.parse()

    # Basic style checks
    style_errors = validate_style(spec)
    assert not style_errors, "Style/Versioning violations:\n- " + "\n- ".join(style_errors)

    # Canonicalize for hashing/compare
    canonical = spec.to_canonical()
    canonical_str = json.dumps(canonical, sort_keys=True, ensure_ascii=False)
    fingerprint = _sha256(canonical_str)

    # Snapshot logic
    snap = load_snapshot()
    regen = os.getenv("REGENERATE_CONTRACT") == "1"

    if snap is None and regen:
        save_snapshot(spec)
        # Ensure it was written correctly
        snap2 = load_snapshot()
        assert snap2 is not None, "Snapshot save failed"
        snap = snap2

    # If snapshot exists, enforce backward compatibility
    if snap is not None:
        compat_errors = check_backward_compatibility(snap, canonical)
        if compat_errors:
            diff_lines = diff_dict(snap, canonical)  # helpful context
            msg = [
                "Backward-compatibility violations detected:",
                *[f"- {e}" for e in compat_errors],
                "",
                "Diff (snapshot -> current):",
                *[f"  {d}" for d in diff_lines],
                "",
                f"Current fingerprint: {fingerprint}",
                f"Proto file: {proto_path}",
            ]
            assert False, "\n".join(msg)
    else:
        # No snapshot and no regeneration: hard fail with precise guidance
        msg = [
            "No contract snapshot found for gRPC v1.",
            f"Expected snapshot: {SNAPSHOT_PATH}",
            "Provide a snapshot or enable snapshot generation via environment variable.",
        ]
        assert False, "\n".join(msg)


def test_grpc_v1_uniqueness_and_sanity():
    """
    Additional hardening checks:
    - Unique field numbers within a message
    - No overlap of reserved tags with actual fields
    - RPCs reference existing message types
    """
    proto_path = discover_proto_file()
    text = _read_text(proto_path)
    spec = ProtoParser(text).parse()
    can = spec.to_canonical()

    msgs = can["messages"]
    svcs = can["services"]

    # Unique tags and reserved vs used
    for mname, m in msgs.items():
        tags = set()
        for num_str in m["fields"].keys():
            num = int(num_str)
            assert num not in tags, f"duplicate field tag in {mname}: {num}"
            tags.add(num)
        for lo, hi in m["reserved_numbers"]:
            for n in range(int(lo), int(hi) + 1):
                assert str(n) not in m["fields"], f"{mname}: reserved tag reused: {n}"

    # RPC types exist as messages
    for sname, s in svcs.items():
        for rname, r in s["rpcs"].items():
            req = r["request_type"].split(".")[-1]
            res = r["response_type"].split(".")[-1]
            assert req in msgs, f"rpc {sname}.{rname}: request type not found: {r['request_type']}"
            assert res in msgs, f"rpc {sname}.{rname}: response type not found: {r['response_type']}"
