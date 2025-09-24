# cybersecurity-core/cybersecurity/network/nac.py
from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union, Callable

# -----------------------------------------------------------------------------
# Logger
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}")

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def normalize_mac(s: str) -> str:
    """
    Normalize a MAC address to 'aa:bb:cc:dd:ee:ff' lowercase.
    Raises ValueError if invalid.
    """
    if not s:
        raise ValueError("empty mac")
    hexdigits = re.findall(r"[0-9A-Fa-f]{2}", s.replace("-", "").replace(":", "").replace(".", ""))
    if len(hexdigits) != 6:
        raise ValueError(f"invalid mac: {s}")
    return ":".join(h.lower() for h in hexdigits)

def safe_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        return "<unrepr>"

# -----------------------------------------------------------------------------
# Domain enums and data
# -----------------------------------------------------------------------------
class AuthMethod(str, Enum):
    DOT1X = "dot1x"
    MAB = "mab"  # MAC Authentication Bypass
    STATIC = "static"

class DecisionType(str, Enum):
    PERMIT = "permit"
    DENY = "deny"
    QUARANTINE = "quarantine"
    LIMITED = "limited"
    REDIRECT = "redirect"
    REAUTH = "reauth"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EndpointStatus(str, Enum):
    UNKNOWN = "unknown"
    AUTHORIZED = "authorized"
    QUARANTINED = "quarantined"
    DENIED = "denied"

@dataclass
class EnforcementAction:
    """
    Declarative description of enforcement to apply on the edge.
    """
    type: DecisionType
    vlan_id: Optional[int] = None
    dacl: Optional[str] = None
    redirect_url: Optional[str] = None
    session_reauth_seconds: Optional[int] = None
    reason: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)  # driver-specific attrs

@dataclass
class AccessDecision:
    decision: DecisionType
    action: EnforcementAction
    policy_name: str
    policy_id: str
    ts: datetime = field(default_factory=utcnow)

@dataclass
class Endpoint:
    mac: str
    ip: Optional[str] = None
    identity: Optional[str] = None         # user or cert CN
    device_type: Optional[str] = None      # e.g. printer, phone
    os: Optional[str] = None               # e.g. ios, windows
    posture_score: Optional[int] = None    # 0..100
    risk: RiskLevel = RiskLevel.LOW
    tags: List[str] = field(default_factory=list)
    status: EndpointStatus = EndpointStatus.UNKNOWN
    last_seen: datetime = field(default_factory=utcnow)
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Session:
    session_id: str
    endpoint_mac: str
    switch_id: str
    port_id: str
    method: AuthMethod
    vlan_current: Optional[int] = None
    started_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    history: List[AccessDecision] = field(default_factory=list)
    sticky_until: Optional[datetime] = None  # suppress frequent policy flips
    last_change_at: Optional[datetime] = None
    changes_in_window: int = 0

@dataclass
class AccessContext:
    """
    Input for policy evaluation (auth request).
    """
    mac: str
    ip: Optional[str]
    identity: Optional[str]
    method: AuthMethod
    eap_success: bool
    cert_subject: Optional[str]
    switch_id: str
    port_id: str
    device_profile: Dict[str, Any] = field(default_factory=dict)
    posture: Dict[str, Any] = field(default_factory=dict)  # agent results
    time: datetime = field(default_factory=utcnow)

# -----------------------------------------------------------------------------
# Policy engine (AST of conditions)
# -----------------------------------------------------------------------------
class CmpOp(str, Enum):
    EQ = "eq"
    NE = "ne"
    IN = "in"
    NIN = "nin"
    GE = "ge"
    GT = "gt"
    LE = "le"
    LT = "lt"
    CIDR = "cidr"
    LIKE = "like"      # substring (case-insensitive)
    PREFIX = "prefix"  # startswith
    SUFFIX = "suffix"  # endswith
    REGEX = "regex"

@dataclass(frozen=True)
class Cond:
    """
    Single predicate: field op value.
    Field supports dotted paths in AccessContext + Endpoint derived map.
    """
    field: str
    op: CmpOp
    value: Any

@dataclass(frozen=True)
class And:
    items: Tuple["Node", ...]

@dataclass(frozen=True)
class Or:
    items: Tuple["Node", ...]

@dataclass(frozen=True)
class Not:
    item: "Node"

Node = Union[Cond, And, Or, Not]

def _get_field_from(ctxmap: Mapping[str, Any], path: str) -> Any:
    cur: Any = ctxmap
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

def _to_map(ctx: AccessContext, ep: Optional[Endpoint]) -> Dict[str, Any]:
    m: Dict[str, Any] = {
        "mac": ctx.mac,
        "ip": ctx.ip,
        "identity": ctx.identity,
        "method": ctx.method.value,
        "eap_success": ctx.eap_success,
        "cert_subject": ctx.cert_subject,
        "switch_id": ctx.switch_id,
        "port_id": ctx.port_id,
        "device": ctx.device_profile,
        "posture": ctx.posture,
        "time_hour": ctx.time.hour,
        "time_wday": ctx.time.weekday(),
    }
    if ep:
        m["endpoint"] = {
            "risk": ep.risk.value,
            "posture_score": ep.posture_score,
            "status": ep.status.value,
            "tags": ep.tags,
            "device_type": ep.device_type,
            "os": ep.os,
        }
    return m

def _ci(s: Optional[str]) -> Optional[str]:
    return s.lower() if isinstance(s, str) else s

def eval_cond(node: Node, ctxmap: Mapping[str, Any]) -> bool:
    if isinstance(node, Cond):
        v = _get_field_from(ctxmap, node.field)
        op = node.op
        val = node.value
        if op == CmpOp.EQ:
            return v == val
        if op == CmpOp.NE:
            return v != val
        if op == CmpOp.IN:
            return v in val if isinstance(val, (list, tuple, set)) else False
        if op == CmpOp.NIN:
            return v not in val if isinstance(val, (list, tuple, set)) else False
        if op == CmpOp.GE:
            return (v is not None) and (v >= val)
        if op == CmpOp.GT:
            return (v is not None) and (v > val)
        if op == CmpOp.LE:
            return (v is not None) and (v <= val)
        if op == CmpOp.LT:
            return (v is not None) and (v < val)
        if op == CmpOp.CIDR:
            try:
                if v is None:
                    return False
                ip = ipaddress.ip_address(str(v))
                net = ipaddress.ip_network(str(val), strict=False)
                return ip in net
            except Exception:
                return False
        if op == CmpOp.LIKE:
            return (_ci(val) or "") in (_ci(v) or "")
        if op == CmpOp.PREFIX:
            return (_ci(v) or "").startswith(_ci(val) or "")
        if op == CmpOp.SUFFIX:
            return (_ci(v) or "").endswith(_ci(val) or "")
        if op == CmpOp.REGEX:
            try:
                return re.search(str(val), safe_str(v)) is not None
            except re.error:
                return False
        return False
    if isinstance(node, And):
        return all(eval_cond(it, ctxmap) for it in node.items)
    if isinstance(node, Or):
        return any(eval_cond(it, ctxmap) for it in node.items)
    if isinstance(node, Not):
        return not eval_cond(node.item, ctxmap)
    return False

# -----------------------------------------------------------------------------
# Policy definition
# -----------------------------------------------------------------------------
@dataclass
class NACPolicy:
    policy_id: str
    name: str
    priority: int
    condition: Node
    # action builder may compute action based on context
    action_builder: Callable[[AccessContext, Optional[Endpoint]], EnforcementAction]
    enabled: bool = True
    description: Optional[str] = None

# -----------------------------------------------------------------------------
# Storage abstraction
# -----------------------------------------------------------------------------
class NACStore:
    """
    Replace with DB/ORM for production.
    """
    # Endpoints
    def upsert_endpoint(self, ep: Endpoint) -> None:  # pragma: no cover - interface
        raise NotImplementedError
    def get_endpoint(self, mac: str) -> Optional[Endpoint]:  # pragma: no cover
        raise NotImplementedError

    # Sessions
    def get_session(self, mac: str, switch_id: str, port_id: str) -> Optional[Session]:  # pragma: no cover
        raise NotImplementedError
    def upsert_session(self, s: Session) -> None:  # pragma: no cover
        raise NotImplementedError
    def end_session(self, session_id: str) -> None:  # pragma: no cover
        raise NotImplementedError

    # Policies
    def list_policies(self) -> List[NACPolicy]:  # pragma: no cover
        raise NotImplementedError
    def add_policy(self, p: NACPolicy) -> None:  # pragma: no cover
        raise NotImplementedError
    def replace_policies(self, items: List[NACPolicy]) -> None:  # pragma: no cover
        raise NotImplementedError

    # Audit
    def add_audit(self, record: Dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError
    def recent_decisions(self, mac: str, window_sec: int) -> List[AccessDecision]:  # pragma: no cover
        raise NotImplementedError

class InMemoryNACStore(NACStore):
    def __init__(self) -> None:
        self._eps: Dict[str, Endpoint] = {}
        self._sess: Dict[str, Session] = {}  # key: mac|switch|port
        self._pol: List[NACPolicy] = []
        self._audit: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def _k(self, mac: str, sw: str, port: str) -> str:
        return f"{mac}|{sw}|{port}"

    def upsert_endpoint(self, ep: Endpoint) -> None:
        with self._lock:
            self._eps[ep.mac] = ep

    def get_endpoint(self, mac: str) -> Optional[Endpoint]:
        with self._lock:
            return self._eps.get(mac)

    def get_session(self, mac: str, switch_id: str, port_id: str) -> Optional[Session]:
        with self._lock:
            return self._sess.get(self._k(mac, switch_id, port_id))

    def upsert_session(self, s: Session) -> None:
        with self._lock:
            self._sess[self._k(s.endpoint_mac, s.switch_id, s.port_id)] = s

    def end_session(self, session_id: str) -> None:
        with self._lock:
            for k, v in list(self._sess.items()):
                if v.session_id == session_id:
                    del self._sess[k]

    def list_policies(self) -> List[NACPolicy]:
        with self._lock:
            return sorted([p for p in self._pol if p.enabled], key=lambda x: (x.priority, x.name))

    def add_policy(self, p: NACPolicy) -> None:
        with self._lock:
            self._pol.append(p)

    def replace_policies(self, items: List[NACPolicy]) -> None:
        with self._lock:
            self._pol = list(items)

    def add_audit(self, record: Dict[str, Any]) -> None:
        with self._lock:
            self._audit.append(record)

    def recent_decisions(self, mac: str, window_sec: int) -> List[AccessDecision]:
        cutoff = utcnow() - timedelta(seconds=window_sec)
        out: List[AccessDecision] = []
        with self._lock:
            for s in self._sess.values():
                if s.endpoint_mac == mac:
                    out.extend([d for d in s.history if d.ts >= cutoff])
        return out

# -----------------------------------------------------------------------------
# Enforcement drivers (stubs)
# -----------------------------------------------------------------------------
class RadiusEnforcer:
    """
    Generates RADIUS attributes to enforce a decision (for NAD integration).
    """
    @staticmethod
    def to_radius_attrs(action: EnforcementAction) -> Dict[str, Any]:
        attrs: Dict[str, Any] = {}
        if action.vlan_id is not None:
            # Standard VLAN attributes (Tunnel-Private-Group-ID is vendor-neutral)
            attrs.update({
                "Tunnel-Type": "VLAN",
                "Tunnel-Medium-Type": "IEEE-802",
                "Tunnel-Private-Group-ID": str(action.vlan_id),
            })
        if action.dacl:
            attrs["Filter-Id"] = action.dacl
        if action.redirect_url and action.type in {DecisionType.REDIRECT, DecisionType.QUARANTINE, DecisionType.LIMITED}:
            # Vendor-specific placeholder (e.g., Cisco-AVPair = 'url-redirect=...')
            attrs["Vendor-Redirect-URL"] = action.redirect_url
        if action.session_reauth_seconds:
            attrs["Session-Timeout"] = action.session_reauth_seconds
        # Pass-through custom attributes if provided
        for k, v in action.attributes.items():
            attrs[k] = v
        return attrs

class SwitchEnforcer:
    """
    Produces high-level switch intents; northbound driver may translate to CLI/NETCONF.
    """
    @staticmethod
    def to_switch_intents(switch_id: str, port_id: str, action: EnforcementAction) -> Dict[str, Any]:
        intents: Dict[str, Any] = {"switch_id": switch_id, "port_id": port_id, "changes": []}
        if action.vlan_id is not None:
            intents["changes"].append({"op": "set_access_vlan", "vlan": action.vlan_id})
        if action.dacl:
            intents["changes"].append({"op": "apply_dacl", "name": action.dacl})
        if action.type == DecisionType.REAUTH and action.session_reauth_seconds:
            intents["changes"].append({"op": "force_reauth_in", "seconds": action.session_reauth_seconds})
        if action.type in {DecisionType.QUARANTINE, DecisionType.REDIRECT} and action.redirect_url:
            intents["changes"].append({"op": "set_redirect", "url": action.redirect_url})
        return intents

# -----------------------------------------------------------------------------
# NAC Engine configuration / policies
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class EnginePolicy:
    flapping_window_seconds: int = 120
    flapping_limit: int = 3
    sticky_seconds: int = 180
    decision_rate_limit: int = 20         # decisions per endpoint per window
    decision_rate_window_seconds: int = 60

# -----------------------------------------------------------------------------
# NAC Engine
# -----------------------------------------------------------------------------
class NACEngine:
    def __init__(self, store: NACStore, engine_policy: Optional[EnginePolicy] = None) -> None:
        self.store = store
        self.cfg = engine_policy or EnginePolicy()
        self._lock = threading.RLock()

    # ---- Policy evaluation ----------------------------------------------------
    def evaluate(self, ctx: AccessContext) -> AccessDecision:
        mac = normalize_mac(ctx.mac)
        # derive endpoint map
        ep = self.store.get_endpoint(mac)
        ctx_map = _to_map(ctx, ep)

        # Apply policies by priority
        decision: Optional[AccessDecision] = None
        for p in self.store.list_policies():
            try:
                if eval_cond(p.condition, ctx_map):
                    act = p.action_builder(ctx, ep)
                    decision = AccessDecision(
                        decision=act.type, action=act, policy_name=p.name, policy_id=p.policy_id
                    )
                    break
            except Exception:
                logger.exception("policy_eval_error policy_id=%s", p.policy_id)

        # Default DENY if nothing matched
        if decision is None:
            act = EnforcementAction(type=DecisionType.DENY, reason="default_deny")
            decision = AccessDecision(decision=DecisionType.DENY, action=act, policy_name="__default__", policy_id="0")

        # Anti-flapping & rate-limit on session level
        sess = self._get_or_create_session(mac, ctx)
        decision = self._stabilize_decision(sess, decision)

        # Update endpoint status
        self._update_endpoint_with_decision(ep, mac, ctx, decision)

        # Persist session history
        sess.history.append(decision)
        sess.updated_at = utcnow()
        sess.last_change_at = decision.ts
        self.store.upsert_session(sess)

        # Audit
        self._audit("decision", {
            "mac": mac, "switch": ctx.switch_id, "port": ctx.port_id, "policy": decision.policy_name,
            "policy_id": decision.policy_id, "decision": decision.decision.value, "action": decision.action.__dict__,
            "time": decision.ts.isoformat()
        })

        return decision

    # ---- Enforcement helpers --------------------------------------------------
    @staticmethod
    def to_radius_attributes(decision: AccessDecision) -> Dict[str, Any]:
        return RadiusEnforcer.to_radius_attrs(decision.action)

    @staticmethod
    def to_switch_intents(ctx: AccessContext, decision: AccessDecision) -> Dict[str, Any]:
        return SwitchEnforcer.to_switch_intents(ctx.switch_id, ctx.port_id, decision.action)

    # ---- Session / endpoint management ---------------------------------------
    def _get_or_create_session(self, mac: str, ctx: AccessContext) -> Session:
        sess = self.store.get_session(mac, ctx.switch_id, ctx.port_id)
        if sess:
            return sess
        sess = Session(
            session_id=str(uuid.uuid4()),
            endpoint_mac=mac,
            switch_id=ctx.switch_id,
            port_id=ctx.port_id,
            method=ctx.method,
        )
        self.store.upsert_session(sess)
        return sess

    def _update_endpoint_with_decision(self, ep: Optional[Endpoint], mac: str, ctx: AccessContext, dec: AccessDecision) -> None:
        new_status = {
            DecisionType.PERMIT: EndpointStatus.AUTHORIZED,
            DecisionType.LIMITED: EndpointStatus.AUTHORIZED,
            DecisionType.REDIRECT: EndpointStatus.AUTHORIZED,
            DecisionType.QUARANTINE: EndpointStatus.QUARANTINED,
            DecisionType.DENY: EndpointStatus.DENIED,
            DecisionType.REAUTH: EndpointStatus.AUTHORIZED,
        }[dec.decision]
        ep = ep or Endpoint(mac=mac)
        ep.ip = ctx.ip or ep.ip
        ep.identity = ctx.identity or ep.identity
        ep.last_seen = utcnow()
        ep.status = new_status
        # optionally update posture/risk if provided
        if "score" in ctx.posture and isinstance(ctx.posture["score"], int):
            ep.posture_score = ctx.posture["score"]
        if "risk" in ctx.posture and ctx.posture["risk"] in {r.value for r in RiskLevel}:
            ep.risk = RiskLevel(ctx.posture["risk"])
        self.store.upsert_endpoint(ep)

    # ---- Stabilization & rate limiting ---------------------------------------
    def _stabilize_decision(self, sess: Session, dec: AccessDecision) -> AccessDecision:
        now = utcnow()
        # Sticky window suppresses flips
        if sess.sticky_until and now < sess.sticky_until and sess.history:
            last = sess.history[-1]
            logger.info("sticky_decision_active keep=%s until=%s", last.decision.value, sess.sticky_until)
            return last

        # Flapping detection
        wnd = self.cfg.flapping_window_seconds
        cutoff = now - timedelta(seconds=wnd)
        recent = [d for d in sess.history if d.ts >= cutoff]
        flips = sum(1 for i in range(1, len(recent)) if recent[i].decision != recent[i-1].decision)
        if flips >= self.cfg.flapping_limit:
            # keep last stable decision and extend sticky
            base = sess.history[-1] if sess.history else dec
            sess.sticky_until = now + timedelta(seconds=self.cfg.sticky_seconds)
            logger.warning("flapping_detected keep=%s sticky=%ss", base.decision.value, self.cfg.sticky_seconds)
            return base

        # Endpoint decision rate limit (simple)
        mac = sess.endpoint_mac
        recent_decisions = self.store.recent_decisions(mac, self.cfg.decision_rate_window_seconds)
        if len(recent_decisions) > self.cfg.decision_rate_limit:
            # freeze to last decision
            base = sess.history[-1] if sess.history else dec
            logger.warning("rate_limit_decisions mac=%s count=%d", mac, len(recent_decisions))
            return base

        return dec

    def _audit(self, event: str, payload: Dict[str, Any]) -> None:
        try:
            rec = {"event": event, "time": utcnow().isoformat(), **payload}
            self.store.add_audit(rec)
        except Exception:
            logger.exception("audit_error")

# -----------------------------------------------------------------------------
# Example action builders
# -----------------------------------------------------------------------------
def act_permit(vlan: Optional[int] = None, dacl: Optional[str] = None, reason: str = "permit") -> Callable[[AccessContext, Optional[Endpoint]], EnforcementAction]:
    def _b(_ctx: AccessContext, _ep: Optional[Endpoint]) -> EnforcementAction:
        return EnforcementAction(type=DecisionType.PERMIT, vlan_id=vlan, dacl=dacl, reason=reason)
    return _b

def act_quarantine(vlan: int, reason: str = "quarantine", redirect_url: Optional[str] = None) -> Callable[[AccessContext, Optional[Endpoint]], EnforcementAction]:
    def _b(_ctx: AccessContext, _ep: Optional[Endpoint]) -> EnforcementAction:
        return EnforcementAction(type=DecisionType.QUARANTINE, vlan_id=vlan, redirect_url=redirect_url, reason=reason)
    return _b

def act_redirect(url: str, vlan: Optional[int] = None, reason: str = "redirect") -> Callable[[AccessContext, Optional[Endpoint]], EnforcementAction]:
    def _b(_ctx: AccessContext, _ep: Optional[Endpoint]) -> EnforcementAction:
        return EnforcementAction(type=DecisionType.REDIRECT, redirect_url=url, vlan_id=vlan, reason=reason)
    return _b

def act_limited(vlan: int, dacl: Optional[str] = None, reason: str = "limited") -> Callable[[AccessContext, Optional[Endpoint]], EnforcementAction]:
    def _b(_ctx: AccessContext, _ep: Optional[Endpoint]) -> EnforcementAction:
        return EnforcementAction(type=DecisionType.LIMITED, vlan_id=vlan, dacl=dacl, reason=reason)
    return _b

def act_deny(reason: str = "deny") -> Callable[[AccessContext, Optional[Endpoint]], EnforcementAction]:
    def _b(_ctx: AccessContext, _ep: Optional[Endpoint]) -> EnforcementAction:
        return EnforcementAction(type=DecisionType.DENY, reason=reason)
    return _b

def act_reauth(timeout_s: int = 300, reason: str = "reauth") -> Callable[[AccessContext, Optional[Endpoint]], EnforcementAction]:
    def _b(_ctx: AccessContext, _ep: Optional[Endpoint]) -> EnforcementAction:
        return EnforcementAction(type=DecisionType.REAUTH, session_reauth_seconds=timeout_s, reason=reason)
    return _b

# -----------------------------------------------------------------------------
# Policy helpers (common conditions)
# -----------------------------------------------------------------------------
def c(field: str, op: CmpOp, value: Any) -> Cond:
    return Cond(field, op, value)

def AND(*nodes: Node) -> And:
    return And(tuple(nodes))

def OR(*nodes: Node) -> Or:
    return Or(tuple(nodes))

def NOT(node: Node) -> Not:
    return Not(node)

# -----------------------------------------------------------------------------
# Default baseline policies (optional to install)
# -----------------------------------------------------------------------------
def build_default_policies(quarantine_vlan: int = 998, guest_vlan: int = 997) -> List[NACPolicy]:
    """
    Priority: lower value -> evaluated earlier.
    """
    policies: List[NACPolicy] = [
        NACPolicy(
            policy_id="10",
            name="Block_Unknown_MAB",
            priority=10,
            condition=AND(
                c("method", CmpOp.EQ, AuthMethod.MAB.value),
                c("eap_success", CmpOp.EQ, False),
                NOT(c("endpoint.device_type", CmpOp.IN, ["printer","pos","camera"]))
            ),
            action_builder=act_quarantine(quarantine_vlan, reason="mab_block"),
            description="Block MAB for unknown devices except allowlisted types"
        ),
        NACPolicy(
            policy_id="20",
            name="Permit_Cert_Based_Wired",
            priority=20,
            condition=AND(
                c("method", CmpOp.EQ, AuthMethod.DOT1X.value),
                c("eap_success", CmpOp.EQ, True),
                c("cert_subject", CmpOp.LIKE, "CN=")  # has certificate subject
            ),
            action_builder=act_permit(vlan=None, dacl=None, reason="dot1x_cert_ok"),
            description="Permit 802.1X with valid cert"
        ),
        NACPolicy(
            policy_id="30",
            name="Quarantine_HighRisk_or_LowPosture",
            priority=30,
            condition=OR(
                c("endpoint.risk", CmpOp.IN, [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]),
                c("endpoint.posture_score", CmpOp.LT, 60),
                c("posture.score", CmpOp.LT, 60),
            ),
            action_builder=act_quarantine(quarantine_vlan, reason="risk_or_posture"),
            description="Quarantine if risk high or posture low"
        ),
        NACPolicy(
            policy_id="40",
            name="Guest_Redirect",
            priority=40,
            condition=AND(
                c("method", CmpOp.EQ, AuthMethod.MAB.value),
                c("endpoint.status", CmpOp.EQ, EndpointStatus.UNKNOWN.value)
            ),
            action_builder=act_redirect("http://captive.portal/guest", vlan=guest_vlan, reason="guest_onboarding"),
            description="Redirect unknown MAB to captive portal"
        ),
        NACPolicy(
            policy_id="90",
            name="Default_Deny",
            priority=90,
            condition=AND(c("mac", CmpOp.REGEX, ".*")),  # always true
            action_builder=act_deny(),
            description="Catch-all deny"
        ),
    ]
    return policies

# -----------------------------------------------------------------------------
# Example integration entrypoints
# -----------------------------------------------------------------------------
def process_radius_access_request(engine: NACEngine, req: Dict[str, Any]) -> Tuple[AccessDecision, Dict[str, Any]]:
    """
    Convert a RADIUS access-request into AccessContext and return a decision with reply attributes.
    `req` is a minimal dict abstraction from your RADIUS server.
    """
    mac_raw = req.get("Calling-Station-Id") or req.get("MAC") or ""
    try:
        mac = normalize_mac(mac_raw)
    except ValueError:
        mac = "00:00:00:00:00:00"

    ctx = AccessContext(
        mac=mac,
        ip=req.get("Framed-IP-Address"),
        identity=req.get("User-Name"),
        method=AuthMethod.DOT1X if req.get("EAP-Message") else AuthMethod.MAB,
        eap_success=bool(req.get("EAP-Success", False)),
        cert_subject=req.get("TLS-Client-Cert-Subject"),
        switch_id=safe_str(req.get("NAS-Identifier") or req.get("NAS-IP-Address") or "unknown"),
        port_id=safe_str(req.get("NAS-Port-Id") or req.get("NAS-Port") or "0"),
        device_profile={"oui": mac[:8], "vendor": req.get("Device-Vendor")},
        posture=req.get("Posture", {}),
        time=utcnow(),
    )
    decision = engine.evaluate(ctx)
    reply_attrs = engine.to_radius_attributes(decision)
    return decision, reply_attrs

def process_dhcp_snoop(engine: NACEngine, event: Mapping[str, Any]) -> None:
    """
    Update endpoint IP/posture from DHCP snooping or IPAM integration.
    event: {"mac": "...", "ip": "...", "switch_id": "...", "port_id": "..."}
    """
    try:
        mac = normalize_mac(safe_str(event.get("mac")))
    except ValueError:
        return
    ep = engine.store.get_endpoint(mac) or Endpoint(mac=mac)
    ip = event.get("ip")
    if ip:
        try:
            ipaddress.ip_address(ip)
            ep.ip = ip
        except Exception:
            pass
    ep.last_seen = utcnow()
    engine.store.upsert_endpoint(ep)
    engine._audit("dhcp_update", {"mac": mac, "ip": ep.ip})

# -----------------------------------------------------------------------------
# Self-test (optional)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    store = InMemoryNACStore()
    engine = NACEngine(store)
    # load default policies
    for p in build_default_policies():
        store.add_policy(p)

    # seed endpoint type
    ep = Endpoint(mac=normalize_mac("AA-BB-CC-11-22-33"), device_type="printer", posture_score=85)
    store.upsert_endpoint(ep)

    req = {
        "Calling-Station-Id": "AA-BB-CC-11-22-33",
        "EAP-Message": None,
        "NAS-Identifier": "sw1",
        "NAS-Port-Id": "Gig1/0/10",
    }
    decision, attrs = process_radius_access_request(engine, req)
    print("decision:", decision.decision.value, decision.policy_name, decision.action)
    print("radius:", json.dumps(attrs, indent=2))
