# cybersecurity-core/tests/contract/test_grpc_v1.proto_contract.py
# SPDX-License-Identifier: Apache-2.0
"""
Industrial gRPC v1 Proto Contract Tests

Purpose:
- Generate a FileDescriptorSet from .proto sources via protoc.
- Validate Protobuf invariants (proto3 syntax, unique field numbers, forbidden ranges).
- Validate gRPC service/method signatures (presence, streaming flags).
- Detect breaking changes against a baseline descriptor set (if provided).

Environment variables (all optional unless noted):
  PROTOC_BIN                 : path to protoc executable (default: "protoc")
  PROTO_SRC_DIR              : directory with .proto sources (default: "cybersecurity-core/proto")
  PROTO_INCLUDE_DIRS         : extra include dirs, colon/semicolon-separated (default: "")
  PROTO_ENTRYPOINTS          : comma-separated .proto entry files; if empty, discover all under PROTO_SRC_DIR
  EXPECT_PACKAGE_SUFFIX      : e.g. "v1" to enforce package versioning (skip if unset)
  EXPECT_DESCRIPTOR_SHA256   : exact SHA256 of normalized descriptor for reproducibility check (optional)
  BASELINE_DESCRIPTOR        : path to baseline .pb (FileDescriptorSet) for breaking-change diff (optional)
  BREAKING_ALLOWLIST         : YAML path with allowlisted breaking items (optional; id format explained below)

Allowlist format (YAML), e.g.:
  services:
    - "package.Service/OldMethod"         # allow removal or signature change
  messages:
    - "package.Message#field_name"        # allow field change/removal
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import pytest
from google.protobuf import descriptor_pb2  # type: ignore

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - yaml is optional, only needed for allowlist
    yaml = None


# ----------------------------- Utilities ----------------------------- #

def _split_paths(value: str) -> List[str]:
    if not value:
        return []
    sep = ";" if platform.system().lower().startswith("win") else ":"
    # Accept both separators to be user-friendly
    parts = re.split(r"[;:]", value)
    return [p for p in (s.strip() for s in parts) if p]


def _discover_proto_files(root: Path) -> List[Path]:
    return sorted(root.rglob("*.proto"))


def _run_protoc_to_descriptor(
    protoc_bin: str,
    proto_paths: List[Path],
    include_dirs: List[Path],
) -> bytes:
    """
    Build a FileDescriptorSet by invoking protoc with:
      --include_imports to make result self-contained.
      (We intentionally do NOT pass --include_source_info to keep descriptor stable.)
    """
    with tempfile.TemporaryDirectory() as td:
        out_path = Path(td) / "descriptor.pb"
        cmd: List[str] = [protoc_bin]
        for inc in include_dirs:
            cmd.extend(["-I", str(inc)])
        # Ensure source dir is also included
        for src in sorted({p.parent for p in proto_paths}):
            cmd.extend(["-I", str(src)])
        cmd.extend(
            [
                "--include_imports",
                f"--descriptor_set_out={out_path}",
            ]
        )
        cmd.extend([str(p) for p in proto_paths])

        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            pytest.skip(f"protoc not found: {protoc_bin}")
        except subprocess.CalledProcessError as e:
            raise AssertionError(
                f"protoc failed with code {e.returncode}\nCMD: {shlex.join(cmd)}\nSTDERR:\n{e.stderr.decode('utf-8', 'ignore')}"
            )
        return out_path.read_bytes()


def _load_descriptor_set(raw: bytes) -> descriptor_pb2.FileDescriptorSet:
    fds = descriptor_pb2.FileDescriptorSet()
    fds.MergeFromString(raw)
    return fds


def _sha256_descriptor(fds: descriptor_pb2.FileDescriptorSet) -> str:
    # Normalize by removing SourceCodeInfo if present for stability.
    # We also sort files by name to get deterministic hash.
    files = sorted(fds.file, key=lambda f: f.name)
    clone = descriptor_pb2.FileDescriptorSet()
    for f in files:
        g = clone.file.add()
        g.CopyFrom(f)
        g.ClearField("source_code_info")
    return hashlib.sha256(clone.SerializeToString()).hexdigest()


# ----------------------------- Model & Indexing ----------------------------- #

@dataclasses.dataclass(frozen=True)
class FieldSig:
    number: int
    type: int
    label: int  # optional/repeated; in proto3 label==1(optional) or 3(repeated)

@dataclasses.dataclass(frozen=True)
class MessageSig:
    full_name: str
    fields: Dict[str, FieldSig]

@dataclasses.dataclass(frozen=True)
class MethodSig:
    name: str
    input_type: str
    output_type: str
    client_streaming: bool
    server_streaming: bool

@dataclasses.dataclass(frozen=True)
class ServiceSig:
    full_name: str
    methods: Dict[str, MethodSig]


@dataclasses.dataclass
class SchemaIndex:
    package_by_file: Dict[str, str]
    syntax_by_file: Dict[str, str]
    services: Dict[str, ServiceSig]            # fq_service_name -> ServiceSig
    messages: Dict[str, MessageSig]            # fq_message_name -> MessageSig

    @staticmethod
    def build(fds: descriptor_pb2.FileDescriptorSet) -> "SchemaIndex":
        pkg_by_file: Dict[str, str] = {}
        syntax_by_file: Dict[str, str] = {}
        messages: Dict[str, MessageSig] = {}
        services: Dict[str, ServiceSig] = {}

        # Build a quick lookup for enums/messages per file to qualify names.
        def qualify(pkg: str, name: str) -> str:
            return f".{pkg}.{name}" if pkg else f".{name}"

        for fd in fds.file:
            pkg = fd.package
            pkg_by_file[fd.name] = pkg
            syntax_by_file[fd.name] = fd.syntax or ""

            # Messages
            def walk_messages(prefix: str, msgs: Iterable[descriptor_pb2.DescriptorProto]):
                for m in msgs:
                    fq = f"{prefix}.{m.name}" if prefix else qualify(pkg, m.name)
                    fields: Dict[str, FieldSig] = {}
                    used_numbers: Set[int] = set()
                    for f in m.field:
                        fields[f.name] = FieldSig(number=f.number, type=f.type, label=f.label)
                        used_numbers.add(f.number)
                    messages[fq] = MessageSig(full_name=fq, fields=fields)
                    # Nested
                    if m.nested_type:
                        walk_messages(fq, m.nested_type)

            walk_messages("", fd.message_type)

            # Services
            for s in fd.service:
                fq_service = qualify(pkg, s.name)
                methods: Dict[str, MethodSig] = {}
                for m in s.method:
                    methods[m.name] = MethodSig(
                        name=m.name,
                        input_type=m.input_type,     # already fully-qualified with leading dot
                        output_type=m.output_type,
                        client_streaming=bool(m.client_streaming),
                        server_streaming=bool(m.server_streaming),
                    )
                services[fq_service] = ServiceSig(full_name=fq_service, methods=methods)

        return SchemaIndex(
            package_by_file=pkg_by_file,
            syntax_by_file=syntax_by_file,
            services=services,
            messages=messages,
        )


# ----------------------------- Assertions / Checks ----------------------------- #

RESERVED_IMPL_RANGE = range(19000, 20000)  # per protobuf implementation reserved

def _assert_proto3_syntax(si: SchemaIndex) -> None:
    bad = {fname: syn for fname, syn in si.syntax_by_file.items() if syn and syn != "proto3"}
    if bad:
        raise AssertionError(f"Non-proto3 files detected: {bad}")

def _assert_no_reserved_impl_tags(si: SchemaIndex) -> None:
    offenders: List[Tuple[str, str, int]] = []
    for msg in si.messages.values():
        for fname, fsig in msg.fields.items():
            if fsig.number in RESERVED_IMPL_RANGE:
                offenders.append((msg.full_name, fname, fsig.number))
    if offenders:
        formatted = "\n".join(f"  {m}#{f}: {n}" for m, f, n in offenders)
        raise AssertionError(
            "Fields using reserved implementation tag range [19000..19999]:\n" + formatted
        )

def _assert_unique_field_numbers(si: SchemaIndex) -> None:
    offenders: List[str] = []
    for msg in si.messages.values():
        seen: Dict[int, str] = {}
        for fname, fsig in msg.fields.items():
            prev = seen.get(fsig.number)
            if prev:
                offenders.append(f"{msg.full_name}: {prev} and {fname} share number {fsig.number}")
            else:
                seen[fsig.number] = fname
    if offenders:
        raise AssertionError("Duplicate field numbers:\n" + "\n".join("  " + o for o in offenders))

def _assert_services_have_methods(si: SchemaIndex) -> None:
    empty = [svc.full_name for svc in si.services.values() if not svc.methods]
    if empty:
        raise AssertionError("Services without methods:\n  " + "\n  ".join(empty))

def _assert_package_suffix(si: SchemaIndex, expected_suffix: str) -> None:
    bad = [f"{fname}:{pkg}" for fname, pkg in si.package_by_file.items() if pkg and not pkg.endswith("." + expected_suffix)]
    if bad:
        raise AssertionError(f"Package(s) not ending with '.{expected_suffix}':\n  " + "\n  ".join(bad))


# ----------------------------- Breaking-change Diff ----------------------------- #

@dataclasses.dataclass(frozen=True)
class BreakingIssue:
    kind: str       # e.g., service_removed, method_removed, method_signature_changed, field_removed, field_changed
    id: str         # stable identifier, e.g., "pkg.Service/Method" or "pkg.Message#field"
    detail: str

def _index_by_name(si: SchemaIndex) -> Tuple[Dict[str, ServiceSig], Dict[str, MessageSig]]:
    return si.services, si.messages

def _diff_breaking(old: SchemaIndex, new: SchemaIndex, allow: Set[str]) -> List[BreakingIssue]:
    issues: List[BreakingIssue] = []

    old_services, old_messages = _index_by_name(old)
    new_services, new_messages = _index_by_name(new)

    # Services removed
    for sname in sorted(set(old_services) - set(new_services)):
        sid = sname
        if sid not in allow:
            issues.append(BreakingIssue("service_removed", sid, f"Service removed: {sname}"))

    # Methods removed or signature-changed
    for sname, old_s in old_services.items():
        new_s = new_services.get(sname)
        if not new_s:
            continue
        # removed methods
        for mname in sorted(set(old_s.methods) - set(new_s.methods)):
            mid = f"{sname}/{mname}"
            if mid not in allow:
                issues.append(BreakingIssue("method_removed", mid, f"Method removed: {mid}"))
        # changed signatures
        for mname, old_m in old_s.methods.items():
            new_m = new_s.methods.get(mname)
            if not new_m:
                continue
            if (
                old_m.input_type != new_m.input_type
                or old_m.output_type != new_m.output_type
                or old_m.client_streaming != new_m.client_streaming
                or old_m.server_streaming != new_m.server_streaming
            ):
                mid = f"{sname}/{mname}"
                if mid not in allow:
                    issues.append(
                        BreakingIssue(
                            "method_signature_changed",
                            mid,
                            f"Signature changed: {mid} "
                            f"[{old_m.input_type} -> {new_m.input_type}; "
                            f"{old_m.output_type} -> {new_m.output_type}; "
                            f"client_stream {old_m.client_streaming}->{new_m.client_streaming}; "
                            f"server_stream {old_m.server_streaming}->{new_m.server_streaming}]",
                        )
                    )

    # Messages: removed fields or changed fields (number/type/label)
    for mname, old_m in old_messages.items():
        new_m = new_messages.get(mname)
        if not new_m:
            # Removing entire message may be OK if not referenced; still report
            mid = mname
            if mid not in allow:
                issues.append(BreakingIssue("message_removed", mid, f"Message removed: {mname}"))
            continue
        # removed fields
        for fname in sorted(set(old_m.fields) - set(new_m.fields)):
            fid = f"{mname}#{fname}"
            if fid not in allow:
                issues.append(BreakingIssue("field_removed", fid, f"Field removed: {fid}"))
        # changed fields
        for fname, old_f in old_m.fields.items():
            new_f = new_m.fields.get(fname)
            if not new_f:
                continue
            if old_f.number != new_f.number or old_f.type != new_f.type or old_f.label != new_f.label:
                fid = f"{mname}#{fname}"
                if fid not in allow:
                    issues.append(
                        BreakingIssue(
                            "field_changed",
                            fid,
                            f"Field changed: {fid} "
                            f"[number {old_f.number}->{new_f.number}; type {old_f.type}->{new_f.type}; label {old_f.label}->{new_f.label}]",
                        )
                    )

    return issues


def _load_allowlist(path: Optional[str]) -> Set[str]:
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        return set()
    if yaml is None:
        raise AssertionError("pyyaml is required to use BREAKING_ALLOWLIST but is not installed")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    out: Set[str] = set()
    for k in ("services", "messages"):
        for item in (data.get(k) or []):
            out.add(str(item))
    return out


# ----------------------------- Pytest Fixtures ----------------------------- #

@pytest.fixture(scope="session")
def descriptor_current() -> descriptor_pb2.FileDescriptorSet:
    protoc_bin = os.getenv("PROTOC_BIN", "protoc")
    src_dir = Path(os.getenv("PROTO_SRC_DIR", "cybersecurity-core/proto")).resolve()
    include_dirs = [src_dir] + [Path(p).resolve() for p in _split_paths(os.getenv("PROTO_INCLUDE_DIRS", ""))]

    entrypoints_env = os.getenv("PROTO_ENTRYPOINTS", "")
    if entrypoints_env.strip():
        proto_files = [Path(p.strip()).resolve() for p in entrypoints_env.split(",") if p.strip()]
    else:
        proto_files = _discover_proto_files(src_dir)

    if not proto_files:
        pytest.skip(f"No .proto files found under {src_dir}")

    raw = _run_protoc_to_descriptor(protoc_bin, proto_files, include_dirs)
    return _load_descriptor_set(raw)


@pytest.fixture(scope="session")
def schema_current(descriptor_current: descriptor_pb2.FileDescriptorSet) -> SchemaIndex:
    return SchemaIndex.build(descriptor_current)


@pytest.fixture(scope="session")
def schema_baseline() -> Optional[SchemaIndex]:
    baseline = os.getenv("BASELINE_DESCRIPTOR", "").strip()
    if not baseline:
        return None
    p = Path(baseline).resolve()
    if not p.exists():
        pytest.skip(f"BASELINE_DESCRIPTOR path not found: {p}")
    raw = p.read_bytes()
    return SchemaIndex.build(_load_descriptor_set(raw))


# ----------------------------- Tests ----------------------------- #

def test_proto3_syntax_only(schema_current: SchemaIndex) -> None:
    _assert_proto3_syntax(schema_current)


def test_no_reserved_impl_field_numbers(schema_current: SchemaIndex) -> None:
    _assert_no_reserved_impl_tags(schema_current)


def test_unique_field_numbers(schema_current: SchemaIndex) -> None:
    _assert_unique_field_numbers(schema_current)


def test_services_have_methods(schema_current: SchemaIndex) -> None:
    _assert_services_have_methods(schema_current)


def test_package_version_suffix(schema_current: SchemaIndex) -> None:
    expected = os.getenv("EXPECT_PACKAGE_SUFFIX", "").strip()
    if not expected:
        pytest.skip("EXPECT_PACKAGE_SUFFIX not set; skipping package suffix enforcement")
    _assert_package_suffix(schema_current, expected)


def test_descriptor_sha256_stability(descriptor_current: descriptor_pb2.FileDescriptorSet) -> None:
    expected = os.getenv("EXPECT_DESCRIPTOR_SHA256", "").strip()
    if not expected:
        pytest.skip("EXPECT_DESCRIPTOR_SHA256 not set; skipping descriptor stability check")
    digest = _sha256_descriptor(descriptor_current)
    assert digest == expected, f"Descriptor SHA256 mismatch: got {digest}, expected {expected}"


def test_breaking_changes_against_baseline(
    schema_current: SchemaIndex,
    schema_baseline: Optional[SchemaIndex],
) -> None:
    if schema_baseline is None:
        pytest.skip("No BASELINE_DESCRIPTOR provided; skipping breaking-change diff")

    allow = _load_allowlist(os.getenv("BREAKING_ALLOWLIST", "").strip())
    issues = _diff_breaking(schema_baseline, schema_current, allow)

    if issues:
        details = "\n".join(f"- [{i.kind}] {i.id} :: {i.detail}" for i in issues)
        raise AssertionError("Breaking changes detected:\n" + details)
