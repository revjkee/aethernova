# security-core/cli/admin.py
"""
security-core admin CLI.

Usage examples:
  python -m security_core.cli.admin iam check \
      --roles-config config/roles.toml \
      --principal subject=u123 roles=orders_reader \
      --action read --resource orders/42 \
      --ctx '{"ip":"10.0.0.5","attributes":{"mfa_passed":true}}'

  python -m security_core.cli.admin authz check \
      --ns config/ns.json --tuples data/tuples.json \
      --object document:doc1 --relation viewer --subject user:alice

  python -m security_core.cli.admin kms jwk --vault https://myvault.vault.azure.net --key my-key
  python -m security_core.cli.admin mtls sign-csr --ca ca/intermediate.pem --key ca/intermediate.key \
      --csr csr.pem --ttl-days 30 --out cert.pem --chain chain.pem

  python -m security_core.cli.admin yara compile --namespace core rules/core --cache ./.yara-cache
  python -m security_core.cli.admin yara scan-file samples/mal.bin --cache ./.yara-cache

  python -m security_core.cli.admin utils token --format base62 --length 43
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import textwrap
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Optional TOML support (stdlib in 3.11+)
try:  # py311+
    import tomllib  # type: ignore
except Exception:
    tomllib = None  # type: ignore

# ------------------------
# Logging / JSON utilities
# ------------------------

LOG = logging.getLogger("security_core.cli")

def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s level=%(levelname)s msg=%(message)s",
    )

def print_json(data: Any) -> None:
    sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")

def load_json_or_toml(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    if path.suffix.lower() in (".json",):
        return json.loads(path.read_text(encoding="utf-8"))
    if path.suffix.lower() in (".toml", ".tml"):
        if tomllib is None:
            raise RuntimeError("tomllib is unavailable; use Python 3.11+ or provide JSON config.")
        return tomllib.loads(path.read_text(encoding="utf-8"))
    # fallback: try JSON
    return json.loads(path.read_text(encoding="utf-8"))

# ------------------------
# IAM (RBAC/ABAC)
# ------------------------

def cmd_iam_check(args: argparse.Namespace) -> int:
    from security.iam.roles import (
        RoleRegistry, RoleBuilder, Principal, RequestContext, AccessEvaluator, TokenInfo,
        Effect, Condition, AllOf, AnyOf, Not, TimeWindowUTC, CIDRMatch, AttributeEquals, RegexMatch, MFARequired,
        builtin_roles,
    )

    # Build roles from config or defaults
    registry = RoleRegistry()
    if args.roles_config:
        cfg_path = Path(args.roles_config)
        cfg = load_json_or_toml(cfg_path)
        roles_cfg = cfg.get("roles", [])
        name_to_builder: Dict[str, RoleBuilder] = {}
        for r in roles_cfg:
            b = RoleBuilder(r["name"], version=str(r.get("version", "1")), description=r.get("description", ""))
            for inh in r.get("inherits", []):
                b.inherit(inh)
            for s in r.get("allow", []):
                b.allow(actions=set(s["actions"]), resources=set(s["resources"]))
            for s in r.get("deny", []):
                b.deny(actions=set(s["actions"]), resources=set(s["resources"]))
            name_to_builder[r["name"]] = b
        for b in name_to_builder.values():
            registry.register(b.build())
    else:
        for r in builtin_roles():
            registry.register(r)
    registry.compile()

    principal = _parse_principal(args.principal)
    ctx = RequestContext(
        ip=(args.ctx.get("ip") if args.ctx else None),
        attributes=(args.ctx.get("attributes") if args.ctx else {}),
    )
    evaluator = AccessEvaluator(registry)
    token = None
    if args.token_scopes or args.token_permissions or args.token_roles:
        token = TokenInfo(
            token_id=None,
            subject=principal.subject,
            scopes=tuple(args.token_scopes or []),
            permissions=tuple(args.token_permissions or []),
            roles=tuple(args.token_roles or []),
        )
    decision = evaluator.check_access(
        principal=principal,
        action=args.action,
        resource=args.resource,
        ctx=ctx,
        token=token,
    )
    print_json({
        "allowed": decision.allowed,
        "effect": (decision.effect.value if decision.effect else None),
        "reason": decision.reason,
        "matched_roles": list(decision.matched_roles),
        "used_scopes": list(decision.used_scopes),
        "matched_statements": [ _stmt_to_dict(s) for s in decision.matched_statements ],
    })
    return 0 if decision.allowed else 3  # 3 => access denied

def _stmt_to_dict(s: Any) -> Dict[str, Any]:
    return {
        "sid": getattr(s, "sid", None),
        "effect": getattr(s, "effect", None).value if getattr(s, "effect", None) else None,
        "actions": list(getattr(s, "actions", [])),
        "resources": list(getattr(s, "resources", [])),
    }

def _parse_principal(spec: Sequence[str]) -> Any:
    # spec: key=value pairs, e.g. subject=u1 roles=admin,orders_reader tenant_id=t1
    from security.iam.roles import Principal
    kv = _pairs_to_dict(spec)
    roles = tuple(_split_csv(kv.get("roles", "")))
    groups = tuple(_split_csv(kv.get("groups", "")))
    attrs = json.loads(kv["attributes"]) if "attributes" in kv else {}
    return Principal(
        subject=kv.get("subject") or kv.get("user_id") or "unknown",
        tenant_id=kv.get("tenant_id"),
        user_id=kv.get("user_id"),
        service_id=kv.get("service_id"),
        roles=roles,
        groups=groups,
        attributes=attrs,
    )

# ------------------------
# ReBAC / Zanzibar
# ------------------------

def cmd_authz_check(args: argparse.Namespace) -> int:
    from security.authz.relationship import (
        ObjectRef, Subject, SubjectType,
        NamespaceRegistry, NamespaceDefinition, RelationDefinition,
        This, ComputedUserset, TupleToUserset, Union, Intersection, Exclusion,
        MemoryRelationshipStore, RelationshipAuthorizer,
    )

    ns = _load_namespace(args.ns)
    tuples = _load_tuples(args.tuples)

    reg = NamespaceRegistry()
    reg.register(ns)

    store = MemoryRelationshipStore()
    # Write tuples
    async def fill_and_check() -> Tuple[bool, Dict[str, Any]]:
        await store.write(tuples)
        engine = RelationshipAuthorizer(registry=reg, store=store)
        obj = _parse_object(args.object)
        subj = _parse_subject(args.subject)
        res = await engine.check(obj, args.relation, subj, context=args.context)
        return res.allowed, {
            "allowed": res.allowed,
            "reason": res.reason,
            "path": list(res.path),
            "zookie": res.at.version,
        }

    allowed, out = asyncio.run(fill_and_check())
    print_json(out)
    return 0 if allowed else 3

def cmd_authz_expand(args: argparse.Namespace) -> int:
    from security.authz.relationship import (
        NamespaceRegistry, MemoryRelationshipStore, RelationshipAuthorizer
    )
    ns = _load_namespace(args.ns)
    tuples = _load_tuples(args.tuples)

    async def run() -> Dict[str, Any]:
        reg = NamespaceRegistry().register(ns)
        store = MemoryRelationshipStore()
        await store.write(tuples)
        engine = RelationshipAuthorizer(registry=reg, store=store)
        obj = _parse_object(args.object)
        res = await engine.expand(obj, args.relation, context=args.context)
        return {
            "at": res.at.version,
            "tree": _expand_to_json(res.tree),
        }
    out = asyncio.run(run())
    print_json(out)
    return 0

def cmd_authz_list(args: argparse.Namespace) -> int:
    from security.authz.relationship import (
        NamespaceRegistry, MemoryRelationshipStore, RelationshipAuthorizer, Subject
    )
    ns = _load_namespace(args.ns)
    tuples = _load_tuples(args.tuples)

    async def run() -> Dict[str, Any]:
        reg = NamespaceRegistry().register(ns)
        store = MemoryRelationshipStore()
        await store.write(tuples)
        engine = RelationshipAuthorizer(registry=reg, store=store)
        subj = _parse_subject(args.subject)
        out = await engine.list_objects(args.namespace, args.relation, subj, limit=args.limit)
        return {
            "namespace": out.namespace,
            "relation": out.relation,
            "object_ids": list(out.object_ids),
            "next_page_token": out.next_page_token,
            "at": out.at.version,
        }
    print_json(asyncio.run(run()))
    return 0

def _load_namespace(path: str):
    from security.authz.relationship import (
        NamespaceDefinition, RelationDefinition,
        This, ComputedUserset, TupleToUserset, Union, Intersection, Exclusion,
    )
    data = load_json_or_toml(Path(path))
    # Expected JSON schema:
    # {
    #   "name": "document",
    #   "relations": {
    #     "viewer": {"union":[ "this", {"ttu": {"tupleset":"parent","computed":"viewer"}} ]},
    #     "parent": "this"
    #   }
    # }
    def parse_expr(node: Any):
        if node == "this":
            return This()
        if isinstance(node, dict):
            if "computed" in node:  # {"computed": "relation"}
                return ComputedUserset(relation=node["computed"])
            if "ttu" in node:
                t = node["ttu"]
                return TupleToUserset(tupleset=t["tupleset"], computed=t["computed"])
            if "union" in node:
                return Union.of(*[parse_expr(x) for x in node["union"]])
            if "intersection" in node:
                return Intersection.of(*[parse_expr(x) for x in node["intersection"]])
            if "exclusion" in node:
                ex = node["exclusion"]
                return Exclusion(base=parse_expr(ex["base"]), subtract=parse_expr(ex["subtract"]))
        raise ValueError(f"Invalid relation expression: {node}")

    rels = {}
    for rname, spec in data["relations"].items():
        expr = parse_expr(spec)
        rels[rname] = RelationDefinition(name=rname, rewrite=expr)
    return NamespaceDefinition(name=data["name"], relations=rels)

def _load_tuples(path: str):
    from security.authz.relationship import RelationTuple, ObjectRef, Subject, SubjectType, CaveatBinding
    # JSON schema: [{"object":"document:doc1","relation":"viewer","subject":"user:alice","caveat":{"name":"cidr_allow","params":{"cidrs":["10.0.0.0/8"]}}}]
    raw = load_json_or_toml(Path(path))
    tuples = []
    for t in raw:
        obj = _parse_object(t["object"])
        subj = _parse_subject(t["subject"])
        cav = None
        if "caveat" in t and t["caveat"]:
            cav = CaveatBinding(name=t["caveat"]["name"], params=t["caveat"].get("params", {}))
        tuples.append(RelationTuple(object=obj, relation=t["relation"], subject=subj, caveat=cav))
    return tuples

def _parse_object(s: str):
    from security.authz.relationship import ObjectRef
    if ":" not in s:
        raise ValueError("object must be 'namespace:object_id'")
    ns, oid = s.split(":", 1)
    return ObjectRef(ns, oid)

def _parse_subject(s: str):
    from security.authz.relationship import Subject, ObjectRef
    if s.startswith("user:"):
        return Subject.user(s.split(":", 1)[1])
    if s.startswith("userset:"):
        # userset:namespace:obj#rel
        u = s[len("userset:") :]
        if "#" not in u or ":" not in u:
            raise ValueError("userset must be userset:ns:obj#rel")
        left, rel = u.split("#", 1)
        ns, oid = left.split(":", 1)
        return Subject.userset(ObjectRef(ns, oid), rel)
    if s.startswith("object:"):
        o = s[len("object:") :]
        return Subject.object(_parse_object(o))
    raise ValueError("subject must be user:<id> | userset:<ns:obj#rel> | object:<ns:obj>")

def _expand_to_json(node) -> Dict[str, Any]:
    return {
        "type": node.type,
        "target": node.target,
        "caveated": node.caveated,
        "tuples": node.tuples,
        "children": [ _expand_to_json(c) for c in getattr(node, "children", ()) ],
    }

# ------------------------
# KMS (Azure Key Vault)
# ------------------------

def _require_azure() -> None:
    try:
        import azure  # type: ignore
    except Exception:
        raise RuntimeError("Azure SDK not installed. Install azure-identity and azure-keyvault-keys.")

def cmd_kms_jwk(args: argparse.Namespace) -> int:
    _require_azure()
    from security.kms.azure_kv import AzureKeyVaultKMS
    kms = AzureKeyVaultKMS(vault_url=args.vault)
    jwk = kms.get_public_jwk(args.key, version=args.version)
    print_json(jwk)
    return 0

def cmd_kms_spki(args: argparse.Namespace) -> int:
    _require_azure()
    from security.kms.azure_kv import AzureKeyVaultKMS
    kms = AzureKeyVaultKMS(vault_url=args.vault)
    spki = kms.get_public_spki(args.key, version=args.version)
    if spki is None:
        raise RuntimeError("SPKI export requires 'cryptography' package")
    print_json({"spki_der_b64": _b64(spki)})
    return 0

def cmd_kms_sign(args: argparse.Namespace) -> int:
    _require_azure()
    from security.kms.azure_kv import AzureKeyVaultKMS
    kms = AzureKeyVaultKMS(vault_url=args.vault)
    sig = kms.sign(args.key, args.alg, _b64d(args.data), prehashed=args.prehashed)
    print_json({"signature_b64": _b64(sig)})
    return 0

def cmd_kms_verify(args: argparse.Namespace) -> int:
    _require_azure()
    from security.kms.azure_kv import AzureKeyVaultKMS
    kms = AzureKeyVaultKMS(vault_url=args.vault)
    ok = kms.verify(args.key, args.alg, _b64d(args.data), _b64d(args.signature), prehashed=args.prehashed)
    print_json({"valid": bool(ok)})
    return 0 if ok else 3

def cmd_kms_encrypt(args: argparse.Namespace) -> int:
    _require_azure()
    from security.kms.azure_kv import AzureKeyVaultKMS
    kms = AzureKeyVaultKMS(vault_url=args.vault)
    alg, ct, tag = kms.encrypt(args.key, args.alg, _b64d(args.plaintext), aad=_maybe_b64d(args.aad))
    print_json({"alg": alg, "ciphertext_b64": _b64(ct), "tag_b64": (_b64(tag) if tag else None)})
    return 0

def cmd_kms_decrypt(args: argparse.Namespace) -> int:
    _require_azure()
    from security.kms.azure_kv import AzureKeyVaultKMS
    kms = AzureKeyVaultKMS(vault_url=args.vault)
    pt = kms.decrypt(args.key, args.alg, _b64d(args.ciphertext), aad=_maybe_b64d(args.aad), auth_tag=_maybe_b64d(args.tag))
    print_json({"plaintext_b64": _b64(pt)})
    return 0

def cmd_kms_wrap(args: argparse.Namespace) -> int:
    _require_azure()
    from security.kms.azure_kv import AzureKeyVaultKMS
    kms = AzureKeyVaultKMS(vault_url=args.vault)
    alg, wrapped = kms.wrap_key(args.key, args.alg, _b64d(args.cek))
    print_json({"alg": alg, "wrapped_b64": _b64(wrapped)})
    return 0

def cmd_kms_unwrap(args: argparse.Namespace) -> int:
    _require_azure()
    from security.kms.azure_kv import AzureKeyVaultKMS
    kms = AzureKeyVaultKMS(vault_url=args.vault)
    cek = kms.unwrap_key(args.key, args.alg, _b64d(args.wrapped))
    print_json({"cek_b64": _b64(cek)})
    return 0

# ------------------------
# mTLS / PKI
# ------------------------

def _require_crypto() -> None:
    try:
        import cryptography  # type: ignore
    except Exception:
        raise RuntimeError("cryptography package is required for mTLS commands")

def cmd_mtls_root(args: argparse.Namespace) -> int:
    _require_crypto()
    from security.mtls.issuer import CertificateAuthority, SubjectInfo, IssuerConfig
    subject = SubjectInfo(common_name=args.cn, organization=args.org)
    ca = CertificateAuthority.create_root(
        subject=subject,
        ttl=_days(args.ttl_days),
        path_len=args.path_len,
        cfg=IssuerConfig(organization=args.org or None, ocsp_url=args.ocsp, ca_issuers_url=args.ca_issuers, crl_distribution_url=args.crl),
    )
    _write_file(args.out_cert, ca.cert.public_bytes)
    _write_file(args.out_key, ca.key.private_bytes)
    print_json({"ok": True})
    return 0

def cmd_mtls_intermediate(args: argparse.Namespace) -> int:
    _require_crypto()
    from security.mtls.issuer import CertificateAuthority, SubjectInfo, load_cert_pem, load_key_pem
    parent_cert = load_cert_pem(Path(args.parent_cert).read_bytes())
    parent_key = load_key_pem(Path(args.parent_key).read_bytes(), password=(args.parent_key_password.encode() if args.parent_key_password else None))
    parent = CertificateAuthority(cert=parent_cert, key=parent_key)
    inter = CertificateAuthority.create_intermediate(parent, subject=SubjectInfo(common_name=args.cn, organization=args.org), ttl=_days(args.ttl_days), path_len=args.path_len)
    _write_file(args.out_cert, inter.cert.public_bytes)
    _write_file(args.out_key, inter.key.private_bytes)
    print_json({"ok": True})
    return 0

def cmd_mtls_sign_csr(args: argparse.Namespace) -> int:
    _require_crypto()
    from security.mtls.issuer import CertificateAuthority, load_cert_pem, load_key_pem, load_csr_pem, dump_cert_pem
    ca_cert = load_cert_pem(Path(args.ca).read_bytes())
    ca_key = load_key_pem(Path(args.key).read_bytes(), password=(args.key_password.encode() if args.key_password else None))
    ca = CertificateAuthority(cert=ca_cert, key=ca_key)
    csr = load_csr_pem(Path(args.csr).read_bytes())
    cert, chain = ca.sign_csr(csr, ttl=_days(args.ttl_days))
    Path(args.out).write_bytes(dump_cert_pem(cert))
    if args.chain:
        Path(args.chain).write_bytes(b"".join(c.public_bytes() for c in chain))
    print_json({"ok": True})
    return 0

def cmd_mtls_crl(args: argparse.Namespace) -> int:
    _require_crypto()
    from security.mtls.issuer import CertificateAuthority, load_cert_pem, load_key_pem
    ca_cert = load_cert_pem(Path(args.ca).read_bytes())
    ca_key = load_key_pem(Path(args.key).read_bytes(), password=(args.key_password.encode() if args.key_password else None))
    ca = CertificateAuthority(cert=ca_cert, key=ca_key)
    revoked = []  # supply via JSON file if needed in future
    crl = ca.make_crl(revoked, next_update_in=_days(args.next_update_days))
    Path(args.out).write_bytes(crl.public_bytes())  # type: ignore[arg-type]
    print_json({"ok": True})
    return 0

# ------------------------
# YARA
# ------------------------

def _require_yara() -> None:
    try:
        import yara  # type: ignore
    except Exception:
        raise RuntimeError("yara-python is required for YARA commands")

def cmd_yara_compile(args: argparse.Namespace) -> int:
    _require_yara()
    from security.threat_detection.rules_yara import YaraConfig, YaraRuleManager, RuleSource
    cfg = YaraConfig(cache_dir=Path(args.cache))
    mgr = YaraRuleManager(cfg)
    srcs = []
    # Each "namespace path" pair from CLI; minimal: one namespace and one path
    srcs.append(RuleSource(namespace=args.namespace, paths=(Path(args.path),)))
    meta = mgr.compile(srcs)
    print_json(asdict(meta))
    return 0

def cmd_yara_scan_file(args: argparse.Namespace) -> int:
    _require_yara()
    from security.threat_detection.rules_yara import YaraConfig, YaraRuleManager
    cfg = YaraConfig(cache_dir=Path(args.cache))
    mgr = YaraRuleManager(cfg)
    if not mgr.refresh_from_cache(args.fingerprint):
        raise RuntimeError("compiled rules not found in cache; run 'yara compile' first")
    res = mgr.scan_file(args.file)
    print_json({
        "target": res.target,
        "matches": [asdict(m) for m in res.matches],
        "stats": asdict(res.stats),
    })
    return 0

# ------------------------
# Utils (crypto_random)
# ------------------------

def cmd_utils_token(args: argparse.Namespace) -> int:
    from security.utils.crypto_random import token_urlsafe, token_hex, token_base62
    if args.format == "urlsafe":
        t = token_urlsafe(args.bytes)
    elif args.format == "hex":
        t = token_hex(args.bytes)
    elif args.format == "base62":
        t = token_base62(args.length)
    else:
        raise ValueError("unknown format")
    print_json({"token": t})
    return 0

def cmd_utils_hkdf(args: argparse.Namespace) -> int:
    from security.utils.crypto_random import hkdf
    okm = hkdf(_b64d(args.ikm), salt=_maybe_b64d(args.salt), info=_maybe_b64d(args.info), length=args.length, hash_name=args.hash)
    print_json({"okm_b64": _b64(okm)})
    return 0

def cmd_utils_nonce(args: argparse.Namespace) -> int:
    from security.utils.crypto_random import NonceManager
    nm = NonceManager()
    n = nm.nonce96(args.label)
    print_json({"nonce_b64": _b64(n)})
    return 0

# ------------------------
# Version / env
# ------------------------

def cmd_version(_: argparse.Namespace) -> int:
    vers: Dict[str, Any] = {"python": sys.version}
    try:
        import azure  # type: ignore
        vers["azure"] = True
    except Exception:
        vers["azure"] = False
    try:
        import cryptography  # type: ignore
        vers["cryptography"] = True
    except Exception:
        vers["cryptography"] = False
    try:
        import yara  # type: ignore
        vers["yara"] = True
    except Exception:
        vers["yara"] = False
    print_json(vers)
    return 0

# ------------------------
# Helpers
# ------------------------

def _b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    import base64
    return base64.b64decode(s.encode("ascii"))

def _maybe_b64d(s: Optional[str]) -> Optional[bytes]:
    return _b64d(s) if s else None

def _split_csv(s: str) -> List[str]:
    return [x.strip() for x in s.split(",") if x.strip()]

def _pairs_to_dict(pairs: Sequence[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for p in pairs:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        out[k.strip()] = v.strip()
    return out

def _days(n: int):
    from datetime import timedelta
    return timedelta(days=int(n))

def _write_file(path: str, exporter) -> None:
    """Exporter is either bytes or a callable that returns bytes (compat with x509 API)."""
    data = exporter() if callable(exporter) else exporter
    Path(path).write_bytes(data)

# ------------------------
# Argument parser
# ------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="security-core-admin", description="security-core admin CLI")
    p.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")

    sp = p.add_subparsers(dest="cmd", required=True)

    # IAM
    iam = sp.add_parser("iam", help="IAM (RBAC/ABAC) commands")
    sp_iam = iam.add_subparsers(dest="sub", required=True)

    iam_check = sp_iam.add_parser("check", help="Check access decision")
    iam_check.add_argument("--roles-config", help="roles config (TOML/JSON); default builtin")
    iam_check.add_argument("--principal", nargs="*", default=(), help="key=value pairs: subject=u1 roles=admin,reader attributes='{\"mfa_passed\":true}'")
    iam_check.add_argument("--action", required=True)
    iam_check.add_argument("--resource", required=True)
    iam_check.add_argument("--ctx", type=json.loads, default=None, help="JSON context: {\"ip\":\"1.2.3.4\",\"attributes\":{}}")
    iam_check.add_argument("--token-scopes", nargs="*", default=[])
    iam_check.add_argument("--token-permissions", nargs="*", default=[])
    iam_check.add_argument("--token-roles", nargs="*", default=[])
    iam_check.set_defaults(func=cmd_iam_check)

    # AUTHZ
    authz = sp.add_parser("authz", help="ReBAC/Zanzibar relationship engine")
    sp_authz = authz.add_subparsers(dest="sub", required=True)

    a_chk = sp_authz.add_parser("check", help="Membership check")
    a_chk.add_argument("--ns", required=True, help="namespace schema JSON/TOML")
    a_chk.add_argument("--tuples", required=True, help="tuples JSON")
    a_chk.add_argument("--object", required=True, help="namespace:object_id")
    a_chk.add_argument("--relation", required=True)
    a_chk.add_argument("--subject", required=True, help="user:<id> | userset:<ns:obj#rel> | object:<ns:obj>")
    a_chk.add_argument("--context", type=json.loads, default=None, help="JSON context for caveats")
    a_chk.set_defaults(func=cmd_authz_check)

    a_exp = sp_authz.add_parser("expand", help="Expand relation tree")
    a_exp.add_argument("--ns", required=True)
    a_exp.add_argument("--tuples", required=True)
    a_exp.add_argument("--object", required=True)
    a_exp.add_argument("--relation", required=True)
    a_exp.add_argument("--context", type=json.loads, default=None)
    a_exp.set_defaults(func=cmd_authz_expand)

    a_ls = sp_authz.add_parser("list", help="List objects visible to subject")
    a_ls.add_argument("--ns", required=True)
    a_ls.add_argument("--tuples", required=True)
    a_ls.add_argument("--namespace", required=True)
    a_ls.add_argument("--relation", required=True)
    a_ls.add_argument("--subject", required=True)
    a_ls.add_argument("--limit", type=int, default=100)
    a_ls.set_defaults(func=cmd_authz_list)

    # KMS
    kms = sp.add_parser("kms", help="Azure Key Vault KMS")
    sp_kms = kms.add_subparsers(dest="sub", required=True)
    for name, fn, argspec in [
        ("jwk", cmd_kms_jwk, [("--vault", True), ("--key", True), ("--version", False)]),
        ("spki", cmd_kms_spki, [("--vault", True), ("--key", True), ("--version", False)]),
    ]:
        sub = sp_kms.add_parser(name)
        for flag, req in argspec:
            sub.add_argument(flag, required=req)
        sub.set_defaults(func=fn)

    ksign = sp_kms.add_subparsers
    s = sp_kms.add_parser("sign")
    s.add_argument("--vault", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--alg", required=True)
    s.add_argument("--data", required=True, help="Base64 of data or digest per --prehashed")
    s.add_argument("--prehashed", action="store_true")
    s.set_defaults(func=cmd_kms_sign)

    v = sp_kms.add_parser("verify")
    v.add_argument("--vault", required=True)
    v.add_argument("--key", required=True)
    v.add_argument("--alg", required=True)
    v.add_argument("--data", required=True)
    v.add_argument("--signature", required=True)
    v.add_argument("--prehashed", action="store_true")
    v.set_defaults(func=cmd_kms_verify)

    e = sp_kms.add_parser("encrypt")
    e.add_argument("--vault", required=True)
    e.add_argument("--key", required=True)
    e.add_argument("--alg", required=True)
    e.add_argument("--plaintext", required=True)
    e.add_argument("--aad")
    e.set_defaults(func=cmd_kms_encrypt)

    d = sp_kms.add_parser("decrypt")
    d.add_argument("--vault", required=True)
    d.add_argument("--key", required=True)
    d.add_argument("--alg", required=True)
    d.add_argument("--ciphertext", required=True)
    d.add_argument("--aad")
    d.add_argument("--tag")
    d.set_defaults(func=cmd_kms_decrypt)

    w = sp_kms.add_parser("wrap")
    w.add_argument("--vault", required=True)
    w.add_argument("--key", required=True)
    w.add_argument("--alg", required=True)
    w.add_argument("--cek", required=True)
    w.set_defaults(func=cmd_kms_wrap)

    uw = sp_kms.add_parser("unwrap")
    uw.add_argument("--vault", required=True)
    uw.add_argument("--key", required=True)
    uw.add_argument("--alg", required=True)
    uw.add_argument("--wrapped", required=True)
    uw.set_defaults(func=cmd_kms_unwrap)

    # mTLS
    mtls = sp.add_parser("mtls", help="mTLS/PKI operations")
    sp_m = mtls.add_subparsers(dest="sub", required=True)

    r = sp_m.add_parser("root", help="Create ROOT CA (self-signed)")
    r.add_argument("--cn", required=True)
    r.add_argument("--org")
    r.add_argument("--ttl-days", type=int, default=3650)
    r.add_argument("--path-len", type=int, default=1)
    r.add_argument("--ocsp")
    r.add_argument("--ca-issuers")
    r.add_argument("--crl")
    r.add_argument("--out-cert", required=True)
    r.add_argument("--out-key", required=True)
    r.set_defaults(func=cmd_mtls_root)

    i = sp_m.add_parser("intermediate", help="Create Intermediate CA")
    i.add_argument("--parent-cert", required=True)
    i.add_argument("--parent-key", required=True)
    i.add_argument("--parent-key-password")
    i.add_argument("--cn", required=True)
    i.add_argument("--org")
    i.add_argument("--ttl-days", type=int, default=1825)
    i.add_argument("--path-len", type=int, default=0)
    i.add_argument("--out-cert", required=True)
    i.add_argument("--out-key", required=True)
    i.set_defaults(func=cmd_mtls_intermediate)

    sc = sp_m.add_parser("sign-csr", help="Sign CSR for leaf cert")
    sc.add_argument("--ca", required=True)
    sc.add_argument("--key", required=True)
    sc.add_argument("--key-password")
    sc.add_argument("--csr", required=True)
    sc.add_argument("--ttl-days", type=int, default=30)
    sc.add_argument("--out", required=True)
    sc.add_argument("--chain")
    sc.set_defaults(func=cmd_mtls_sign_csr)

    crl = sp_m.add_parser("crl", help="Generate CRL")
    crl.add_argument("--ca", required=True)
    crl.add_argument("--key", required=True)
    crl.add_argument("--key-password")
    crl.add_argument("--next-update-days", type=int, default=7)
    crl.add_argument("--out", required=True)
    crl.set_defaults(func=cmd_mtls_crl)

    # YARA
    yara = sp.add_parser("yara", help="YARA rules management")
    sp_y = yara.add_subparsers(dest="sub", required=True)

    yc = sp_y.add_parser("compile", help="Compile YARA namespace")
    yc.add_argument("--namespace", required=True)
    yc.add_argument("path", help="rules dir or file")
    yc.add_argument("--cache", required=True)
    yc.set_defaults(func=cmd_yara_compile)

    ys = sp_y.add_parser("scan-file", help="Scan file with compiled rules")
    ys.add_argument("file")
    ys.add_argument("--cache", required=True)
    ys.add_argument("--fingerprint", required=True)
    ys.set_defaults(func=cmd_yara_scan_file)

    # Utils
    u = sp.add_parser("utils", help="crypto utilities")
    sp_u = u.add_subparsers(dest="sub", required=True)

    ut = sp_u.add_parser("token", help="Generate token")
    ut.add_argument("--format", choices=("urlsafe", "hex", "base62"), default="urlsafe")
    ut.add_argument("--bytes", type=int, default=32, help="for urlsafe/hex")
    ut.add_argument("--length", type=int, default=43, help="for base62")
    ut.set_defaults(func=cmd_utils_token)

    uh = sp_u.add_parser("hkdf", help="HKDF derive key")
    uh.add_argument("--ikm", required=True, help="Base64 IKM")
    uh.add_argument("--salt", help="Base64 salt")
    uh.add_argument("--info", help="Base64 info")
    uh.add_argument("--length", type=int, default=32)
    uh.add_argument("--hash", default="sha256")
    uh.set_defaults(func=cmd_utils_hkdf)

    un = sp_u.add_parser("nonce", help="Generate 96-bit AEAD nonce for label")
    un.add_argument("--label", required=True)
    un.set_defaults(func=cmd_utils_nonce)

    # Version
    ver = sp.add_parser("version", help="Show environment/version info")
    ver.set_defaults(func=cmd_version)

    return p

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        LOG.error(str(e))
        return 2
    except ValueError as e:
        LOG.error(str(e))
        return 2
    except RuntimeError as e:
        LOG.error(str(e))
        return 2
    except KeyboardInterrupt:
        LOG.error("interrupted")
        return 130
    except Exception as e:
        LOG.exception("unhandled error: %s", e)
        return 1

if __name__ == "__main__":
    sys.exit(main())
