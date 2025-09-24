# security-core/api/graphql/schema.py
# Industrial GraphQL schema for PKI & CRL operations (Ariadne + async SQLAlchemy).
# Dependencies: ariadne, ariadne[asgi], fastapi, pydantic, cryptography, sqlalchemy[asyncio]
# Optional: python-multipart (если будет upload), uvicorn for serving.

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from ariadne import (
    QueryType, make_executable_schema, gql, ScalarType, ObjectType
)
from ariadne.asgi import GraphQL
from fastapi import Request
from pydantic import BaseModel, Field

# --- Optional cryptography (graceful degrade) ---
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448
    from cryptography.x509.oid import NameOID, ExtensionOID
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

# =============================================================================
# SDL (Schema Definition Language)
# =============================================================================

type_defs = gql("""
scalar Hex
scalar Base64
scalar JSON
scalar Long

""" + r"""
"PKI input certificate container"
input CertInput {
  pem: String
  derB64: Base64
}

"Validate chain request"
input ValidateChainInput {
  leaf: CertInput!
  chain: [CertInput!] = []
  anchors: [CertInput!]
  hostname: String
  ekuOids: [String!]
  atTimeEpoch: Long
  revocationMode: String = "none" # none|crl|ocsp|ocsp_or_crl (delegated externally if validator present)
  timeoutSec: Float = 2.0
}

"OCSP-like request"
input OcspLikeInput {
  leaf: CertInput
  issuer: CertInput
  serialHex: Hex
  issuerDnDerSha256Hex: Hex
  authorityKeyIdHex: Hex
}

"Parsed extension (simplified)"
type ParsedExtension {
  id: String!
  critical: Boolean!
  value: JSON
}

"Parsed certificate"
type ParsedCert {
  subject: JSON!
  issuer: JSON!
  serialHex: Hex!
  notBefore: Long!
  notAfter: Long!
  signatureAlgoOid: String
  spkiAlgorithm: String
  spkiSha256Hex: Hex!
  issuerDnDerSha256Hex: Hex!
  akiHex: Hex
  skiHex: Hex
  sanDNS: [String!]!
  sanIP: [String!]!
  keyUsage: JSON!
  ext: [ParsedExtension!]!
}

"Validation result"
type ValidateResult {
  status: String!        # valid|invalid
  reasons: [String!]!
  pathLen: Int
  checkedAt: Long!
  usedRevocation: String
}

"OCSP-like response"
type OcspLike {
  status: String!        # good|revoked|unknown
  reason: String
  revocationDate: Long
}

"CRL object (metadata only)"
type Crl {
  id: ID!
  issuerDnHashHex: Hex!
  authorityKeyIdHex: Hex
  isDelta: Boolean!
  crlNumber: String
  baseCrlNumber: String
  thisUpdate: Long!
  nextUpdate: Long
  sourceUris: [String!]
}

"CRL entry"
type CrlEntry {
  id: ID!
  crlId: ID!
  certSerialHex: Hex!
  revocationDate: Long!
  reason: String
  invalidityDate: Long
}

"Relay-style pagination"
type PageInfo {
  endCursor: String
  hasNextPage: Boolean!
}

type CrlEdge { cursor: String!, node: Crl! }
type CrlConnection {
  edges: [CrlEdge!]!
  pageInfo: PageInfo!
  totalCount: Int!
}

type CrlEntryEdge { cursor: String!, node: CrlEntry! }
type CrlEntryConnection {
  edges: [CrlEntryEdge!]!
  pageInfo: PageInfo!
  totalCount: Int!
}

"CRL filters"
input CrlFilter {
  issuerDnHashHex: Hex
  authorityKeyIdHex: Hex
  isDelta: Boolean
  updatedAfter: Long
}

"CRL entry filters"
input CrlEntryFilter {
  issuerDnHashHex: Hex!
  authorityKeyIdHex: Hex!
  # Exactly one of:
  serialHex: Hex
  crlId: ID
}

type Query {
  parseCert(input: CertInput!): ParsedCert!
  validateChain(input: ValidateChainInput!): ValidateResult!
  ocspStatus(input: OcspLikeInput!): OcspLike!

  "Return latest CRL (DER) for issuer/AKI; base64-encoded DER"
  crlLatest(issuerDnDerSha256Hex: Hex!, akiHex: Hex, delta: Boolean = false): Base64!

  "List CRLs with Relay-style pagination"
  crls(filter: CrlFilter, first: Int = 20, after: String): CrlConnection!

  "List CRL entries with Relay-style pagination"
  crlEntries(filter: CrlEntryFilter!, first: Int = 100, after: String): CrlEntryConnection!
}
""")

# =============================================================================
# Scalars
# =============================================================================

hex_scalar = ScalarType("Hex")
b64_scalar = ScalarType("Base64")
json_scalar = ScalarType("JSON")
long_scalar = ScalarType("Long")

@hex_scalar.serializer
def serialize_hex(v: Any) -> str:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray, memoryview)):
        return binascii.hexlify(bytes(v)).decode("ascii")
    if isinstance(v, str):
        h = v.lower().strip()
        # accept 0x prefix
        if h.startswith("0x"):
            h = h[2:]
        # validate hex
        binascii.unhexlify(h or "00")
        return h
    raise TypeError("Hex must be bytes or hex-string")

@hex_scalar.value_parser
def parse_hex(v: Any) -> bytes:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        try:
            return binascii.unhexlify(s)
        except Exception as e:
            raise ValueError(f"Invalid hex: {e}")
    raise ValueError("Hex must be string or bytes")

@b64_scalar.serializer
def serialize_b64(v: Any) -> str:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(v)).decode("ascii")
    if isinstance(v, str):
        # assume already base64
        return v
    raise TypeError("Base64 must be bytes or base64-string")

@b64_scalar.value_parser
def parse_b64(v: Any) -> bytes:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, str):
        try:
            return base64.b64decode(v, validate=True)
        except Exception as e:
            raise ValueError(f"Invalid base64: {e}")
    raise ValueError("Base64 must be string or bytes")

@json_scalar.serializer
def serialize_json(v: Any) -> Any:
    # Ariadne will JSON-encode response itself
    return v

@json_scalar.value_parser
def parse_json(v: Any) -> Any:
    return v

@long_scalar.serializer
def serialize_long(v: Any) -> int:
    if v is None:
        return None
    return int(v)

@long_scalar.value_parser
def parse_long(v: Any) -> int:
    return int(v)

# =============================================================================
# Helpers
# =============================================================================

def _now_epoch() -> int:
    return int(time.time())

def _bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def _issuer_dn_der_sha256(cert: "x509.Certificate") -> bytes:
    return hashlib.sha256(cert.issuer.public_bytes(serialization.Encoding.DER)).digest()

def _spki_sha256(cert: "x509.Certificate") -> bytes:
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).digest()

def _serial_to_der_content_bytes(serial: int) -> bytes:
    if serial < 0:
        raise ValueError("Negative serial unsupported")
    h = f"{serial:x}"
    if len(h) % 2:
        h = "0" + h
    b = binascii.unhexlify(h)
    if b and (b[0] & 0x80):
        b = b"\x00" + b
    if not b:
        b = b"\x00"
    return b

def _name_to_map(name: "x509.Name") -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for rdn in name.rdns:
        for attr in rdn:
            key = attr.oid.dotted_string
            out.setdefault(key, []).append(attr.value)
    # aliases
    def add_alias(oid, alias):
        vals = out.get(oid, [])
        if vals:
            out.setdefault(alias, vals)
    add_alias(NameOID.COMMON_NAME.dotted_string, "CN")
    add_alias(NameOID.ORGANIZATION_NAME.dotted_string, "O")
    add_alias(NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "OU")
    add_alias(NameOID.COUNTRY_NAME.dotted_string, "C")
    add_alias(NameOID.STATE_OR_PROVINCE_NAME.dotted_string, "ST")
    add_alias(NameOID.LOCALITY_NAME.dotted_string, "L")
    return out

def _load_cert(ci: Dict[str, Optional[str]]) -> "x509.Certificate":
    if not HAVE_CRYPTO:
        raise ValueError("cryptography not available")
    pem = ci.get("pem")
    derB64 = ci.get("derB64")
    if pem:
        return x509.load_pem_x509_certificate(pem.encode("utf-8"))
    if derB64:
        return x509.load_der_x509_certificate(base64.b64decode(derB64, validate=True))
    raise ValueError("Provide pem or derB64")

def _hostname_matches(cert: "x509.Certificate", hostname: str) -> bool:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = san.get_values_for_type(x509.DNSName)
        from cryptography.x509 import DNSName  # ensure import
        # naive match: wildcard aware
        import fnmatch
        return any(fnmatch.fnmatch(hostname, n) for n in names)
    except Exception:
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            import fnmatch
            return fnmatch.fnmatch(hostname, cn)
        except Exception:
            return False

def _eku_satisfies(cert: "x509.Certificate", required: List[str]) -> bool:
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        have = {oid.dotted_string for oid in eku}
        return all(req in have for req in required)
    except Exception:
        return not required

# =============================================================================
# Resolvers
# =============================================================================

query = QueryType()

@query.field("parseCert")
async def resolve_parse_cert(_, info, input):
    if not HAVE_CRYPTO:
        raise ValueError("cryptography not available")
    cert = _load_cert(input)
    subject = _name_to_map(cert.subject)
    issuer = _name_to_map(cert.issuer)
    serial_hex = f"{cert.serial_number:x}"
    spki_sha = _spki_sha256(cert)
    issuer_hash = _issuer_dn_der_sha256(cert)

    san_dns: List[str] = []
    san_ip: List[str] = []
    key_usage: Dict[str, bool] = {}
    aki_hex = None
    ski_hex = None
    ext_list: List[Dict[str, Any]] = []

    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        val: Any = None
        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            san = ext.value
            san_dns = san.get_values_for_type(x509.DNSName)
            san_ip = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
            val = {"dns": san_dns, "ip": san_ip}
        elif ext.oid == ExtensionOID.KEY_USAGE:
            ku = ext.value
            key_usage = {
                "digital_signature": ku.digital_signature,
                "content_commitment": ku.content_commitment,
                "key_encipherment": ku.key_encipherment,
                "data_encipherment": ku.data_encipherment,
                "key_agreement": ku.key_agreement,
                "key_cert_sign": ku.key_cert_sign,
                "crl_sign": ku.crl_sign,
                "encipher_only": getattr(ku, "encipher_only", False),
                "decipher_only": getattr(ku, "decipher_only", False),
            }
            val = key_usage
        elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            aki = ext.value
            if aki.key_identifier:
                aki_hex = _bytes_to_hex(aki.key_identifier)
            val = {"key_id_hex": aki_hex}
        elif ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            ski = ext.value
            ski_hex = _bytes_to_hex(ski.digest)
            val = {"key_id_hex": ski_hex}
        else:
            val = str(ext.value)
        ext_list.append({"id": oid, "critical": bool(ext.critical), "value": val})

    try:
        sig_oid = cert.signature_algorithm_oid.dotted_string
    except Exception:
        sig_oid = None

    try:
        pk = cert.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            spki_alg = "RSA"
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            spki_alg = f"EC-{pk.curve.name}"
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            spki_alg = "Ed25519"
        elif isinstance(pk, ed448.Ed448PublicKey):
            spki_alg = "Ed448"
        else:
            spki_alg = pk.__class__.__name__
    except Exception:
        spki_alg = None

    return {
        "subject": subject,
        "issuer": issuer,
        "serialHex": serial_hex,
        "notBefore": int(cert.not_valid_before.timestamp()),
        "notAfter": int(cert.not_valid_after.timestamp()),
        "signatureAlgoOid": sig_oid,
        "spkiAlgorithm": spki_alg,
        "spkiSha256Hex": spki_sha,
        "issuerDnDerSha256Hex": issuer_hash,
        "akiHex": aki_hex,
        "skiHex": ski_hex,
        "sanDNS": san_dns,
        "sanIP": san_ip,
        "keyUsage": key_usage,
        "ext": ext_list,
    }

@query.field("validateChain")
async def resolve_validate_chain(_, info, input):
    if not HAVE_CRYPTO:
        raise ValueError("cryptography not available")
    req: Request = info.context["request"]
    leaf = _load_cert(input["leaf"])
    inters = [_load_cert(c) for c in input.get("chain", [])]
    anchors = [_load_cert(c) for c in input.get("anchors") or []] or getattr(req.app.state, "trust_anchors", None)
    hostname = input.get("hostname")
    eku_oids = input.get("ekuOids") or []
    at_epoch = input.get("atTimeEpoch") or _now_epoch()
    rev_mode = input.get("revocationMode", "none")
    timeout = float(input.get("timeoutSec", 2.0))

    # Delegate to external validator if present
    validator = getattr(req.app.state, "pki_validator", None)
    if validator is not None and hasattr(validator, "validate"):
        try:
            result = await asyncio.wait_for(
                validator.validate(leaf, inters, anchors, hostname, eku_oids, at_epoch, rev_mode, timeout=timeout),
                timeout=timeout + 0.1
            )
            return {
                "status": "valid" if result.get("valid") else "invalid",
                "reasons": result.get("reasons", []),
                "pathLen": result.get("path_len"),
                "checkedAt": _now_epoch(),
                "usedRevocation": result.get("revocation"),
            }
        except asyncio.TimeoutError:
            raise ValueError("PKI validator timeout")
        except Exception as e:
            logger = getattr(req.app.state, "audit_logger", None) or getattr(req.app.state, "logger", None)
            if logger:
                logger.error("external_validator_error", extra={"error": str(e)})
            # fallthrough to local

    # Local best-effort validation
    reasons: List[str] = []
    if not (leaf.not_valid_before.timestamp() <= at_epoch <= leaf.not_valid_after.timestamp()):
        reasons.append("leaf time invalid")
    if eku_oids and not _eku_satisfies(leaf, eku_oids):
        reasons.append("EKU not satisfied")
    if hostname and not _hostname_matches(leaf, hostname):
        reasons.append("hostname mismatch")

    def verify_issued_by(child: "x509.Certificate", issuer: "x509.Certificate") -> Optional[str]:
        try:
            pk = issuer.public_key()
            data = child.tbs_certificate_bytes
            sig = child.signature
            sig_hash = child.signature_hash_algorithm  # type: ignore[attr-defined]
            if isinstance(pk, rsa.RSAPublicKey):
                pk.verify(sig, data, padding.PKCS1v15(), sig_hash)
            elif isinstance(pk, ec.EllipticCurvePublicKey):
                pk.verify(sig, data, ec.ECDSA(sig_hash))
            elif isinstance(pk, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                pk.verify(sig, data)
            else:
                return "unsupported issuer key"
            return None
        except Exception as e:
            return f"signature invalid: {e}"

    chain_all = [leaf] + inters
    path_ok = True
    for i in range(len(chain_all) - 1):
        c = chain_all[i]
        iss = chain_all[i + 1]
        if c.issuer != iss.subject:
            reasons.append(f"chain[{i}] issuer != subject")
            path_ok = False
        else:
            err = verify_issued_by(c, iss)
            if err:
                reasons.append(f"chain[{i}] {err}")
                path_ok = False

    # Anchor check if provided
    anchor_found = False
    last = chain_all[-1]
    if anchors:
        for a in anchors:
            if last.issuer == a.subject and verify_issued_by(last, a) is None:
                anchor_found = True
                break
    else:
        # allow self-signed last (trust semantics outside)
        try:
            if last.issuer == last.subject and verify_issued_by(last, last) is None:
                anchor_found = True
        except Exception:
            pass

    if not path_ok:
        reasons.append("path build failed")
    if not anchor_found:
        reasons.append("no trust anchor")

    return {
        "status": "valid" if not reasons else "invalid",
        "reasons": reasons,
        "pathLen": len(chain_all) if not reasons else None,
        "checkedAt": _now_epoch(),
        "usedRevocation": "none" if rev_mode == "none" else "not_performed_local",
    }

@query.field("ocspStatus")
async def resolve_ocsp_status(_, info, input):
    req: Request = info.context["request"]
    engine = getattr(req.app.state, "db_engine", None)
    if engine is None:
        raise ValueError("DB engine not configured")

    issuer_dn_hash: Optional[bytes] = None
    aki: Optional[bytes] = None
    serial_bytes: Optional[bytes] = None

    if input.get("leaf") and input.get("issuer"):
        if not HAVE_CRYPTO:
            raise ValueError("cryptography not available")
        leaf = _load_cert(input["leaf"])
        issuer_dn_hash = _issuer_dn_der_sha256(leaf)
        try:
            aki_ext = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
            aki = aki_ext.key_identifier or None
        except Exception:
            aki = None
        if aki is None and input.get("issuer"):
            issuer = _load_cert(input["issuer"])
            try:
                ski_ext = issuer.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
                aki = ski_ext.digest
            except Exception:
                pass
        serial_bytes = _serial_to_der_content_bytes(leaf.serial_number)
    else:
        issuer_dn_hash = input.get("issuerDnDerSha256Hex")
        aki = input.get("authorityKeyIdHex")
        serial_hex = input.get("serialHex")
        if not (issuer_dn_hash and aki and serial_hex):
            raise ValueError("Provide leaf+issuer or serialHex+issuerDnDerSha256Hex+authorityKeyIdHex")
        serial_bytes = serial_hex

    if issuer_dn_hash is None or aki is None or serial_bytes is None:
        return {"status": "unknown"}

    from sqlalchemy import text
    q = text("""
        SELECT reason_enum::text, EXTRACT(EPOCH FROM revocation_date)::bigint AS ts
        FROM security.current_revocations
        WHERE issuer_dn_hash = :issuer_dn_hash
          AND authority_key_id = :aki
          AND cert_serial_sha256 = security.sha256(:serial_bytes)
        LIMIT 1
    """)
    async with engine.connect() as conn:
        row = await conn.execute(q, dict(issuer_dn_hash=issuer_dn_hash, aki=aki, serial_bytes=serial_bytes))
        rec = row.first()

    if rec:
        reason, ts = rec
        return {"status": "revoked", "reason": reason, "revocationDate": int(ts)}
    return {"status": "good"}

@query.field("crlLatest")
async def resolve_crl_latest(_, info, issuerDnDerSha256Hex, akiHex=None, delta=False):
    req: Request = info.context["request"]
    engine = getattr(req.app.state, "db_engine", None)
    if engine is None:
        raise ValueError("DB engine not configured")
    from sqlalchemy import text
    if delta:
        q = text("""
            WITH latest_full AS (
              SELECT DISTINCT ON (issuer_dn_hash, COALESCE(authority_key_id, '\x'::bytea))
                     id, issuer_dn_hash, authority_key_id, crl_number, this_update
              FROM security.crl
              WHERE is_delta = false
                AND issuer_dn_hash = :issuer
                AND (:aki IS NULL OR COALESCE(authority_key_id, '\x'::bytea) = :aki)
              ORDER BY issuer_dn_hash, COALESCE(authority_key_id, '\x'::bytea), this_update DESC, crl_number DESC NULLS LAST
            )
            SELECT d.signed_der
            FROM security.crl d
            JOIN latest_full f
              ON d.is_delta = true
             AND d.issuer_dn_hash = f.issuer_dn_hash
             AND COALESCE(d.authority_key_id, '\x'::bytea) = COALESCE(f.authority_key_id, '\x'::bytea)
             AND d.base_crl_number = f.crl_number
            ORDER BY d.this_update DESC
            LIMIT 1
        """)
    else:
        q = text("""
            SELECT signed_der
            FROM security.crl
            WHERE is_delta = false
              AND issuer_dn_hash = :issuer
              AND (:aki IS NULL OR COALESCE(authority_key_id, '\x'::bytea) = :aki)
            ORDER BY this_update DESC, crl_number DESC NULLS LAST
            LIMIT 1
        """)
    async with engine.connect() as conn:
        row = await conn.execute(q, dict(issuer=issuerDnDerSha256Hex, aki=akiHex))
        rec = row.first()
    if not rec:
        raise ValueError("CRL not found")
    der: bytes = rec[0]
    return der  # Base64 scalar will serialize

# Connection helpers
def _encode_cursor(kind: str, id_: int) -> str:
    return base64.b64encode(f"{kind}:{id_}".encode("ascii")).decode("ascii")

def _decode_cursor(cursor: Optional[str], kind: str) -> int:
    if not cursor:
        return 0
    try:
        raw = base64.b64decode(cursor).decode("ascii")
        prefix, sid = raw.split(":", 1)
        if prefix != kind:
            return 0
        return int(sid)
    except Exception:
        return 0

@query.field("crls")
async def resolve_crls(_, info, filter=None, first: int = 20, after: Optional[str] = None):
    req: Request = info.context["request"]
    engine = getattr(req.app.state, "db_engine", None)
    if engine is None:
        raise ValueError("DB engine not configured")

    first = max(1, min(first, 200))
    after_id = _decode_cursor(after, "crl")

    where = ["id > :after_id"]
    params: Dict[str, Any] = {"after_id": after_id}

    if filter:
        if filter.get("issuerDnHashHex") is not None:
            where.append("issuer_dn_hash = :issuer")
            params["issuer"] = filter["issuerDnHashHex"]
        if filter.get("authorityKeyIdHex") is not None:
            where.append("COALESCE(authority_key_id, '\x'::bytea) = :aki")
            params["aki"] = filter["authorityKeyIdHex"]
        if filter.get("isDelta") is not None:
            where.append("is_delta = :is_delta")
            params["is_delta"] = bool(filter["isDelta"])
        if filter.get("updatedAfter") is not None:
            where.append("this_update > to_timestamp(:updated_after)")
            params["updated_after"] = int(filter["updatedAfter"])

    where_sql = " AND ".join(where)
    from sqlalchemy import text
    q = text(f"""
        SELECT id, issuer_dn_hash, authority_key_id, is_delta, crl_number, base_crl_number,
               EXTRACT(EPOCH FROM this_update)::bigint AS this_update,
               EXTRACT(EPOCH FROM next_update)::bigint AS next_update,
               source_uris
        FROM security.crl
        WHERE {where_sql}
        ORDER BY id
        LIMIT :limit
    """)
    count_q = text(f"SELECT COUNT(*) FROM security.crl WHERE {where_sql}")

    async with engine.connect() as conn:
        rows = (await conn.execute(q, {**params, "limit": first + 1})).fetchall()
        total = (await conn.execute(count_q, params)).scalar_one()

    edges = []
    for r in rows[:first]:
        node = {
            "id": r.id,
            "issuerDnHashHex": r.issuer_dn_hash,
            "authorityKeyIdHex": r.authority_key_id,
            "isDelta": r.is_delta,
            "crlNumber": str(r.crl_number) if r.crl_number is not None else None,
            "baseCrlNumber": str(r.base_crl_number) if r.base_crl_number is not None else None,
            "thisUpdate": int(r.this_update),
            "nextUpdate": int(r.next_update) if r.next_update is not None else None,
            "sourceUris": list(r.source_uris) if r.source_uris is not None else None,
        }
        edges.append({"cursor": _encode_cursor("crl", r.id), "node": node})

    has_next = len(rows) > first
    end_cursor = edges[-1]["cursor"] if edges else None

    return {"edges": edges, "pageInfo": {"endCursor": end_cursor, "hasNextPage": has_next}, "totalCount": int(total)}

@query.field("crlEntries")
async def resolve_crl_entries(_, info, filter, first: int = 100, after: Optional[str] = None):
    req: Request = info.context["request"]
    engine = getattr(req.app.state, "db_engine", None)
    if engine is None:
        raise ValueError("DB engine not configured")

    first = max(1, min(first, 1000))
    after_id = _decode_cursor(after, "crle")

    issuer = filter["issuerDnHashHex"]
    aki = filter["authorityKeyIdHex"]
    serial_hex = filter.get("serialHex")
    crl_id = filter.get("crlId")

    where = ["e.id > :after_id"]
    params: Dict[str, Any] = {"after_id": after_id, "issuer": issuer, "aki": aki}

    if serial_hex is not None and crl_id is not None:
        raise ValueError("Provide either serialHex or crlId, not both")

    from sqlalchemy import text
    if serial_hex is not None:
        where.append("r.issuer_dn_hash = :issuer AND COALESCE(r.authority_key_id, '\\x'::bytea) = :aki")
        where.append("e.cert_serial_sha256 = security.sha256(:serial_bytes)")
        params["serial_bytes"] = serial_hex
        join_sql = "JOIN security.crl r ON r.id = e.crl_id"
    elif crl_id is not None:
        where.append("e.crl_id = :crl_id")
        params["crl_id"] = int(crl_id)
        join_sql = "JOIN security.crl r ON r.id = e.crl_id AND r.issuer_dn_hash = :issuer AND COALESCE(r.authority_key_id, '\\x'::bytea) = :aki"
    else:
        join_sql = "JOIN security.crl r ON r.id = e.crl_id AND r.issuer_dn_hash = :issuer AND COALESCE(r.authority_key_id, '\\x'::bytea) = :aki"

    where_sql = " AND ".join(where)
    q = text(f"""
        SELECT e.id, e.crl_id, e.cert_serial_bytes,
               EXTRACT(EPOCH FROM e.revocation_date)::bigint AS rev_date,
               e.reason_enum::text AS reason, EXTRACT(EPOCH FROM e.invalidity_date)::bigint AS invalidity
        FROM security.crl_entry e
        {join_sql}
        WHERE {where_sql}
        ORDER BY e.id
        LIMIT :limit
    """)
    count_q = text(f"""
        SELECT COUNT(*)
        FROM security.crl_entry e
        {join_sql}
        WHERE {where_sql}
    """)

    async with engine.connect() as conn:
        rows = (await conn.execute(q, {**params, "limit": first + 1})).fetchall()
        total = (await conn.execute(count_q, params)).scalar_one()

    edges = []
    for r in rows[:first]:
        edges.append({
            "cursor": _encode_cursor("crle", r.id),
            "node": {
                "id": r.id,
                "crlId": r.crl_id,
                "certSerialHex": r.cert_serial_bytes,  # Hex scalar will serialize bytes -> hex
                "revocationDate": int(r.rev_date),
                "reason": r.reason,
                "invalidityDate": int(r.invalidity) if r.invalidity is not None else None,
            }
        })

    has_next = len(rows) > first
    end_cursor = edges[-1]["cursor"] if edges else None
    return {"edges": edges, "pageInfo": {"endCursor": end_cursor, "hasNextPage": has_next}, "totalCount": int(total)}

# =============================================================================
# Depth/Complexity Limits (simple, fast)
# =============================================================================

MAX_DEPTH = int(os.getenv("GRAPHQL_MAX_DEPTH", "12"))
MAX_COMPLEXITY = int(os.getenv("GRAPHQL_MAX_COMPLEXITY", "50000"))

def _calc_depth(selection_set, depth=0) -> int:
    maxd = depth
    if not selection_set:
        return maxd
    for sel in selection_set.selections:
        if getattr(sel, "selection_set", None):
            maxd = max(maxd, _calc_depth(sel.selection_set, depth + 1))
    return maxd

def _estimate_complexity(node, variables) -> int:
    # very rough estimator: each field = 1; connections multiply by 'first'
    cost = 0
    if not getattr(node, "selection_set", None):
        return 1
    for sel in node.selection_set.selections:
        c = 1
        name = getattr(sel, "name", None)
        if name and name.value in ("crls", "crlEntries"):
            args = {arg.name.value: arg.value for arg in sel.arguments or []}
            first = 20
            if "first" in args:
                v = args["first"]
                if v.kind == "IntValue":
                    first = int(v.value)
                elif v.kind == "Variable":
                    first = variables.get(v.name.value, first)
            c = max(1, min(int(first), 2000))
        if getattr(sel, "selection_set", None):
            c *= _estimate_complexity(sel, variables)
        cost += c
    return cost

async def context_value_fn(request: Request):
    return {"request": request, "started": time.perf_counter()}

def error_formatter(error, debug):  # pragma: no cover
    # Hide internal errors details
    try:
        message = error.message
    except Exception:
        message = "Internal error"
    return {"message": message, "path": error.path, "locations": error.locations}

def validation_rules_fn(ctx, document):
    # depth check
    depths = [_calc_depth(op.selection_set, 1) for op in document.definitions if getattr(op, "selection_set", None)]
    if any(d > MAX_DEPTH for d in depths):
        raise ValueError(f"Query depth exceeds limit {MAX_DEPTH}")
    # complexity check
    # estimate per operation
    from graphql.language.ast import OperationDefinition
    total_cost = 0
    for defn in document.definitions:
        if isinstance(defn, OperationDefinition):
            variables = ctx.get("request").json() if hasattr(ctx.get("request"), "json") else {}
            total_cost += _estimate_complexity(defn, variables if isinstance(variables, dict) else {})
    if total_cost > MAX_COMPLEXITY:
        raise ValueError(f"Query complexity exceeds limit {MAX_COMPLEXITY} (est={total_cost})")

# =============================================================================
# Schema / App builder
# =============================================================================

def build_schema():
    return make_executable_schema(
        type_defs,
        query,
        hex_scalar,
        b64_scalar,
        json_scalar,
        long_scalar,
    )

def build_graphql_app(app) -> GraphQL:
    """
    Пример интеграции:
      app.state.db_engine = <AsyncEngine>
      app.state.trust_anchors = [<x509.Certificate>, ...]  # опционально
      app.state.pki_validator = <object with async validate(...)>  # опционально
      app.state.audit_logger = logger  # опционально
      app.add_route("/graphql", build_graphql_app(app))
    """
    schema = build_schema()
    return GraphQL(
        schema,
        context_value=context_value_fn,
        error_formatter=error_formatter,
        debug=False,
        validation_rules=validation_rules_fn,
    )
