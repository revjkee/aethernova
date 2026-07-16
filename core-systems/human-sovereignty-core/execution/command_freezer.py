# path: human-sovereignty-core/execution/command_freezer.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from human_sovereignty_core.bootstrap.invariants import (
    DecisionContext,
    enforce as enforce_invariants,
    get_default_policy,
    SovereigntyPolicy,
)


class FreezeError(RuntimeError):
    pass


class CommandDenied(FreezeError):
    pass


class TokenInvalid(FreezeError):
    pass


class TokenExpired(FreezeError):
    pass


class RiskLevel(Enum):
    SAFE = "safe"
    SENSITIVE = "sensitive"
    DANGEROUS = "dangerous"


@dataclass(frozen=True)
class CommandSpec:
    """
    A normalized command description independent from any specific executor.
    """
    program: str
    args: Tuple[str, ...] = field(default_factory=tuple)
    cwd: Optional[str] = None
    env: Mapping[str, str] = field(default_factory=dict)
    stdin: Optional[str] = None  # for audit only; should be redacted upstream if sensitive

    def canonical(self) -> Dict[str, Any]:
        return {
            "program": self.program,
            "args": list(self.args),
            "cwd": self.cwd,
            "env": _canonicalize_env(self.env),
            "stdin": _redact_stdin(self.stdin),
        }

    def fingerprint(self) -> str:
        payload = _json_dumps_canonical(self.canonical())
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FreezePolicy:
    """
    Deny-by-default policy for command execution.
    """
    policy_id: str = "human-sovereignty-command-freezer-v1"
    fail_closed: bool = True

    # Allowlist of executable names/programs (regex against basename or full).
    allow_program_patterns: Tuple[str, ...] = (
        r"^echo$",
        r"^printf$",
        r"^cat$",
        r"^ls$",
        r"^pwd$",
        r"^whoami$",
        r"^id$",
        r"^uname$",
        r"^python(\d+(\.\d+)*)?$",
        r"^node$",
        r"^npm$",
        r"^pnpm$",
        r"^yarn$",
        r"^git$",
        r"^curl$",
        r"^wget$",
        r"^docker$",
        r"^kubectl$",
        r"^helm$",
        r"^terraform$",
    )

    # Deny patterns for programs regardless of allowlist.
    deny_program_patterns: Tuple[str, ...] = (
        r"^rm$",
        r"^dd$",
        r"^mkfs(\..+)?$",
        r"^shutdown$",
        r"^reboot$",
        r"^poweroff$",
        r"^chown$",
        r"^chmod$",
        r"^useradd$",
        r"^usermod$",
        r"^passwd$",
        r"^sudo$",
        r"^su$",
        r"^iptables$",
        r"^nft$",
    )

    # Argument-level deny patterns (matched against joined args string)
    deny_arg_patterns: Tuple[str, ...] = (
        r"\brm\b.*\b-rf\b",
        r"\b--privileged\b",
        r"\b--net=host\b",
        r"\b--cap-add=ALL\b",
        r"\b--device\b",
        r"\b/system32\b",
        r"\b/etc/shadow\b",
        r"\b\.ssh\b",
        r"\bknown_hosts\b",
        r"\bid_rsa\b",
        r"\bPrivateKey\b",
    )

    # Environment keys that must never be passed through.
    deny_env_keys: Tuple[str, ...] = (
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GCP_PRIVATE_KEY",
        "AZURE_CLIENT_SECRET",
        "OPENAI_API_KEY",
        "TOKEN",
        "PASSWORD",
        "SECRET",
    )

    # Soft limits
    max_arg_len: int = 2048
    max_args: int = 256
    max_env_pairs: int = 128

    # Unfreeze token TTL
    max_unfreeze_ttl_seconds: int = 600  # 10 minutes


@dataclass(frozen=True)
class DecisionGate:
    """
    Gate configuration for linking execution to decision context.
    """
    require_decision_context: bool = True
    require_invariants_enforced: bool = True


@dataclass(frozen=True)
class FreezeDecision:
    allowed: bool
    risk: RiskLevel
    reasons: Tuple[str, ...]
    command_fingerprint: str
    policy_id: str
    checked_at_utc: str

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise CommandDenied("; ".join(self.reasons))


@dataclass(frozen=True)
class UnfreezeToken:
    """
    Short-lived token allowing execution of a specific command fingerprint.
    """
    token_id: str
    command_fingerprint: str
    issued_at_utc: _dt.datetime
    expires_at_utc: _dt.datetime
    bound_human_id: Optional[str]
    bound_request_id: Optional[str]
    signature: str

    def is_expired(self, now_utc: Optional[_dt.datetime] = None) -> bool:
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        return now >= self.expires_at_utc

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "command_fingerprint": self.command_fingerprint,
            "issued_at_utc": _iso_utc(self.issued_at_utc),
            "expires_at_utc": _iso_utc(self.expires_at_utc),
            "bound_human_id": self.bound_human_id,
            "bound_request_id": self.bound_request_id,
            "signature": self.signature,
        }


class CommandFreezer:
    """
    Centralized guardrail to freeze command execution without explicit human sovereignty guarantees.

    Core properties:
    - Deny-by-default with explicit allow patterns.
    - Fail-closed on parsing/validation ambiguity.
    - Optional "unfreeze token" bound to command fingerprint and decision context.
    """

    def __init__(
        self,
        *,
        policy: Optional[FreezePolicy] = None,
        sovereignty_policy: Optional[SovereigntyPolicy] = None,
        decision_gate: Optional[DecisionGate] = None,
        hmac_secret: Optional[bytes] = None,
    ) -> None:
        self._policy = policy or FreezePolicy()
        self._sovereignty_policy = sovereignty_policy or get_default_policy()
        self._gate = decision_gate or DecisionGate()

        secret = hmac_secret or _load_hmac_secret()
        self._hmac_secret = secret

        self._compiled_allow = [re.compile(p) for p in self._policy.allow_program_patterns]
        self._compiled_deny = [re.compile(p) for p in self._policy.deny_program_patterns]
        self._compiled_deny_args = [re.compile(p, flags=re.IGNORECASE) for p in self._policy.deny_arg_patterns]

        self._lock = threading.RLock()

    @property
    def policy(self) -> FreezePolicy:
        return self._policy

    def evaluate(
        self,
        cmd: CommandSpec,
        *,
        now_utc: Optional[_dt.datetime] = None,
        decision_context: Optional[DecisionContext] = None,
        unfreeze_token: Optional[Union[str, Mapping[str, Any], UnfreezeToken]] = None,
    ) -> FreezeDecision:
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        checked_at = _iso_utc(now)

        fp = cmd.fingerprint()
        reasons: List[str] = []
        risk = RiskLevel.SAFE

        try:
            _validate_cmd_shape(cmd, self._policy, reasons)
            _apply_env_guard(cmd, self._policy, reasons)
            prog = _program_basename(cmd.program)

            if _matches_any(self._compiled_deny, prog) or _matches_any(self._compiled_deny, cmd.program):
                reasons.append("denied_program")
                risk = RiskLevel.DANGEROUS

            if not _matches_any(self._compiled_allow, prog) and not _matches_any(self._compiled_allow, cmd.program):
                reasons.append("program_not_allowlisted")
                risk = max(risk, RiskLevel.SENSITIVE, key=_risk_rank)

            joined_args = " ".join(cmd.args)
            for rx in self._compiled_deny_args:
                if rx.search(joined_args):
                    reasons.append("denied_argument_pattern")
                    risk = RiskLevel.DANGEROUS
                    break

            # Decision context enforcement (human sovereignty)
            if self._gate.require_decision_context and decision_context is None:
                reasons.append("missing_decision_context")
                risk = RiskLevel.DANGEROUS

            if decision_context is not None and self._gate.require_invariants_enforced:
                # Enforce sovereignty invariants (fail-closed).
                enforce_invariants(decision_context, policy=self._sovereignty_policy, now_utc=now)

            # If policy denies, allow only if valid unfreeze token is presented and bound to this command.
            if reasons:
                tok = None
                if unfreeze_token is not None:
                    tok = self._parse_token(unfreeze_token)
                    self._verify_token(tok, now_utc=now)
                    if tok.command_fingerprint != fp:
                        raise TokenInvalid("token not bound to this command")
                    if decision_context is not None:
                        if tok.bound_request_id and tok.bound_request_id != decision_context.request_id:
                            raise TokenInvalid("token bound_request_id mismatch")
                        if tok.bound_human_id and decision_context.mandate and tok.bound_human_id != decision_context.mandate.human_id:
                            raise TokenInvalid("token bound_human_id mismatch")
                if tok is not None:
                    # Override denial with explicit short-lived token (still audited by design).
                    return FreezeDecision(
                        allowed=True,
                        risk=RiskLevel.SENSITIVE,
                        reasons=tuple(["allowed_by_unfreeze_token"]),
                        command_fingerprint=fp,
                        policy_id=self._policy.policy_id,
                        checked_at_utc=checked_at,
                    )

            allowed = len(reasons) == 0
            return FreezeDecision(
                allowed=allowed,
                risk=risk,
                reasons=tuple(reasons),
                command_fingerprint=fp,
                policy_id=self._policy.policy_id,
                checked_at_utc=checked_at,
            )

        except Exception as e:
            if self._policy.fail_closed:
                return FreezeDecision(
                    allowed=False,
                    risk=RiskLevel.DANGEROUS,
                    reasons=tuple(["evaluation_error", e.__class__.__name__]),
                    command_fingerprint=fp,
                    policy_id=self._policy.policy_id,
                    checked_at_utc=checked_at,
                )
            raise

    def enforce(
        self,
        cmd: CommandSpec,
        *,
        now_utc: Optional[_dt.datetime] = None,
        decision_context: Optional[DecisionContext] = None,
        unfreeze_token: Optional[Union[str, Mapping[str, Any], UnfreezeToken]] = None,
    ) -> FreezeDecision:
        decision = self.evaluate(cmd, now_utc=now_utc, decision_context=decision_context, unfreeze_token=unfreeze_token)
        decision.raise_if_denied()
        return decision

    def issue_unfreeze_token(
        self,
        cmd: CommandSpec,
        *,
        ttl_seconds: int,
        decision_context: Optional[DecisionContext] = None,
        bound_human_id: Optional[str] = None,
        now_utc: Optional[_dt.datetime] = None,
    ) -> UnfreezeToken:
        """
        Issues a short-lived unfreeze token bound to a specific command fingerprint.
        Intended use: human-approved override for a blocked command.
        """
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        ttl = int(ttl_seconds)

        if ttl <= 0:
            raise FreezeError("ttl_seconds must be positive")
        if ttl > self._policy.max_unfreeze_ttl_seconds:
            raise FreezeError("ttl_seconds exceeds max_unfreeze_ttl_seconds")

        fp = cmd.fingerprint()
        token_id = secrets.token_hex(16)
        exp = now + _dt.timedelta(seconds=ttl)

        bound_request_id = decision_context.request_id if decision_context is not None else None
        if bound_human_id is None and decision_context is not None and decision_context.mandate is not None:
            bound_human_id = decision_context.mandate.human_id

        payload = {
            "token_id": token_id,
            "command_fingerprint": fp,
            "issued_at_utc": _iso_utc(now),
            "expires_at_utc": _iso_utc(exp),
            "bound_human_id": bound_human_id,
            "bound_request_id": bound_request_id,
        }
        sig = self._sign(payload)
        return UnfreezeToken(
            token_id=token_id,
            command_fingerprint=fp,
            issued_at_utc=now,
            expires_at_utc=exp,
            bound_human_id=bound_human_id,
            bound_request_id=bound_request_id,
            signature=sig,
        )

    def _sign(self, payload: Mapping[str, Any]) -> str:
        msg = _json_dumps_canonical(_canonicalize(payload)).encode("utf-8")
        mac = hmac.new(self._hmac_secret, msg, hashlib.sha256).hexdigest()
        return mac

    def _parse_token(self, tok: Union[str, Mapping[str, Any], UnfreezeToken]) -> UnfreezeToken:
        if isinstance(tok, UnfreezeToken):
            return tok
        if isinstance(tok, str):
            try:
                data = json.loads(tok)
            except Exception as e:
                raise TokenInvalid("token string is not valid json") from e
        elif isinstance(tok, Mapping):
            data = dict(tok)
        else:
            raise TokenInvalid("unsupported token type")

        try:
            issued = _parse_dt_utc(data["issued_at_utc"])
            exp = _parse_dt_utc(data["expires_at_utc"])
            return UnfreezeToken(
                token_id=str(data["token_id"]),
                command_fingerprint=str(data["command_fingerprint"]),
                issued_at_utc=issued,
                expires_at_utc=exp,
                bound_human_id=(str(data["bound_human_id"]) if data.get("bound_human_id") is not None else None),
                bound_request_id=(str(data["bound_request_id"]) if data.get("bound_request_id") is not None else None),
                signature=str(data["signature"]),
            )
        except KeyError as e:
            raise TokenInvalid(f"missing field: {e}") from e

    def _verify_token(self, tok: UnfreezeToken, *, now_utc: Optional[_dt.datetime] = None) -> None:
        now = now_utc or _dt.datetime.now(tz=_dt.timezone.utc)
        if tok.issued_at_utc.tzinfo is None or tok.expires_at_utc.tzinfo is None:
            raise TokenInvalid("token datetimes must be timezone-aware")
        if tok.expires_at_utc <= tok.issued_at_utc:
            raise TokenInvalid("token expires_at_utc must be after issued_at_utc")
        if now >= tok.expires_at_utc:
            raise TokenExpired("token expired")

        payload = {
            "token_id": tok.token_id,
            "command_fingerprint": tok.command_fingerprint,
            "issued_at_utc": _iso_utc(tok.issued_at_utc),
            "expires_at_utc": _iso_utc(tok.expires_at_utc),
            "bound_human_id": tok.bound_human_id,
            "bound_request_id": tok.bound_request_id,
        }
        expected = self._sign(payload)
        if not hmac.compare_digest(expected, tok.signature):
            raise TokenInvalid("token signature mismatch")


def _validate_cmd_shape(cmd: CommandSpec, pol: FreezePolicy, reasons: List[str]) -> None:
    if not cmd.program or not str(cmd.program).strip():
        reasons.append("missing_program")
        return
    if len(cmd.args) > pol.max_args:
        reasons.append("too_many_args")
    for a in cmd.args:
        if a is None:
            reasons.append("arg_none")
            continue
        if len(str(a)) > pol.max_arg_len:
            reasons.append("arg_too_long")
    if cmd.env and len(cmd.env) > pol.max_env_pairs:
        reasons.append("too_many_env_pairs")


def _apply_env_guard(cmd: CommandSpec, pol: FreezePolicy, reasons: List[str]) -> None:
    if not cmd.env:
        return
    for k in cmd.env.keys():
        ks = str(k)
        for denied in pol.deny_env_keys:
            if denied.lower() in ks.lower():
                reasons.append("denied_env_key_present")
                return


def _program_basename(path: str) -> str:
    # Avoid os.path.basename ambiguity with trailing slashes.
    p = str(path).strip().replace("\\", "/")
    p = p[:-1] if p.endswith("/") else p
    return p.split("/")[-1]


def _matches_any(regexes: Sequence[re.Pattern], value: str) -> bool:
    for rx in regexes:
        try:
            if rx.match(value):
                return True
        except Exception:
            continue
    return False


def _risk_rank(r: RiskLevel) -> int:
    return {RiskLevel.SAFE: 0, RiskLevel.SENSITIVE: 1, RiskLevel.DANGEROUS: 2}[r]


def _load_hmac_secret() -> bytes:
    """
    Loads HMAC secret from environment. Fail-closed if missing.
    """
    raw = os.environ.get("HUMAN_SOVEREIGNTY_FREEZER_HMAC_SECRET")
    if raw is None or not raw.strip():
        # Fail-closed: generate ephemeral secret if not provided to avoid runtime crash,
        # but note: tokens will not be verifiable across process restarts.
        # This is safer than allowing unsigned tokens.
        return secrets.token_bytes(32)
    return raw.encode("utf-8")


def _iso_utc(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        raise FreezeError("datetime must be timezone-aware")
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_dt_utc(value: Any) -> _dt.datetime:
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            raise TokenInvalid("datetime must be timezone-aware")
        return value.astimezone(_dt.timezone.utc)
    if not isinstance(value, str):
        raise TokenInvalid("datetime must be ISO-8601 string")
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError as e:
        raise TokenInvalid("invalid datetime format") from e
    if dt.tzinfo is None:
        raise TokenInvalid("datetime must include timezone")
    return dt.astimezone(_dt.timezone.utc)


def _json_dumps_canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonicalize(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (bool, int, float, str)):
        return obj
    if dataclasses.is_dataclass(obj):
        return _canonicalize(dataclasses.asdict(obj))
    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        for k in sorted(obj.keys(), key=lambda x: str(x)):
            out[str(k)] = _canonicalize(obj[k])
        return out
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_canonicalize(x) for x in obj]
    if isinstance(obj, _dt.datetime):
        return {"__datetime__": _iso_utc(obj)} if obj.tzinfo else {"__datetime__": "naive"}
    return {"__repr__": repr(obj)}


def _canonicalize_env(env: Mapping[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k in sorted(env.keys(), key=lambda x: str(x)):
        out[str(k)] = str(env[k])
    return out


def _redact_stdin(stdin: Optional[str]) -> Optional[str]:
    if stdin is None:
        return None
    s = str(stdin)
    if len(s) <= 256:
        return s
    return s[:256] + "...(truncated)"
