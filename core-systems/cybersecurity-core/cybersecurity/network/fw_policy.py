# cybersecurity-core/cybersecurity/network/fw_policy.py
# -*- coding: utf-8 -*-
"""
Industrial firewall policy model, validation, simulation and exporters.

Python: 3.11+

Features:
- Data model: AddressObject/Group, ServiceObject/Group, Rule, Policy
- Address parsing: IPv4/IPv6 CIDR, wildcard "any", and IP ranges ("a.b.c.d-e.f.g.h")
- Service parsing: proto tcp/udp/icmp/any, single port, ranges "80-90", lists "80,443", wildcard "any"
- Time windows: optional day-of-week and daily intervals (24h roll-over supported)
- Validation:
    * schema consistency, unknown references
    * conflict and shadow detection (first-match semantics)
- Simulation: evaluate packet decision (ingress/egress)
- Exporters:
    * nftables (text rules with sets)
    * iptables (commands list)
    * AWS Security Group (JSON dict)
    * Azure NSG (JSON dict)
- Policy diff: add/remove/update by stable rule signatures
- Loading: from JSON or YAML (PyYAML optional)
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, time as dtime, timedelta
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union

# Optional YAML support
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

Protocol = Literal["tcp", "udp", "icmp", "any"]
Direction = Literal["ingress", "egress"]
Action = Literal["allow", "deny", "reject"]

_IANA_PORTS = {
    "http": 80,
    "https": 443,
    "ssh": 22,
    "rdp": 3389,
    "dns": 53,
    "smtp": 25,
    "imap": 143,
    "imaps": 993,
    "pop3": 110,
    "pop3s": 995,
    "ntp": 123,
    "mysql": 3306,
    "postgresql": 5432,
    "redis": 6379,
    "kafka": 9092,
    "ldap": 389,
    "ldaps": 636,
}


def _now_ts() -> float:
    return time.time()


def _norm_name(s: str) -> str:
    return re.sub(r"[^a-z0-9_\-\.]+", "_", s.strip().lower())


def _sha(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
    return sha256(raw).hexdigest()


# -----------------------------------------------------------------------------
# Address and Service models
# -----------------------------------------------------------------------------

@dataclass(slots=True)
class AddressObject:
    name: str
    # values: list of strings in formats: CIDR (e.g. 10.0.0.0/24), IP, range "a-b", "any", "::/0"
    values: List[str]

    def networks(self) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for v in self.values:
            v = v.strip()
            if v.lower() == "any":
                nets.append(ipaddress.ip_network("0.0.0.0/0"))
                nets.append(ipaddress.ip_network("::/0"))
                continue
            if "-" in v and "/" not in v:
                # IP range
                a, b = v.split("-", 1)
                a_ip = ipaddress.ip_address(a.strip())
                b_ip = ipaddress.ip_address(b.strip())
                # collapse to minimal set of CIDRs
                nets.extend(ipaddress.summarize_address_range(a_ip, b_ip))
                continue
            # else CIDR or single IP
            nets.append(ipaddress.ip_network(v, strict=False))
        return nets

    def contains_ip(self, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        for n in self.networks():
            if ip.version != n.version:
                continue
            if ip in n:
                return True
        return False


@dataclass(slots=True)
class AddressGroup:
    name: str
    members: List[str]  # names of AddressObject or inline CIDR/IP/range strings

    def expand(self, addr_map: Dict[str, AddressObject]) -> AddressObject:
        vals: List[str] = []
        for m in self.members:
            key = _norm_name(m)
            if key in addr_map:
                vals.extend(addr_map[key].values)
            else:
                vals.append(m)
        return AddressObject(name=self.name, values=vals)


def _parse_port_item(token: str) -> List[Tuple[int, int]]:
    token = token.strip().lower()
    if not token or token == "any":
        return [(0, 65535)]
    if token in _IANA_PORTS:
        p = int(_IANA_PORTS[token])
        return [(p, p)]
    if token.isdigit():
        p = int(token)
        return [(p, p)]
    if "-" in token:
        a, b = token.split("-", 1)
        return [(int(a), int(b))]
    # list "80,443"
    parts = [t for t in token.split(",") if t.strip()]
    ranges: List[Tuple[int, int]] = []
    for p in parts:
        ranges.extend(_parse_port_item(p))
    return ranges


@dataclass(slots=True)
class ServiceObject:
    name: str
    protocol: Protocol
    ports: List[str]  # tokens like "80", "80-90", "80,443", "any", "http"

    def port_ranges(self) -> List[Tuple[int, int]]:
        ranges: List[Tuple[int, int]] = []
        for t in self.ports:
            ranges.extend(_parse_port_item(t))
        # normalize and merge overlaps
        rng = sorted(ranges)
        merged: List[Tuple[int, int]] = []
        for s, e in rng:
            if not merged or s > merged[-1][1] + 1:
                merged.append((s, e))
            else:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        return merged

    def matches(self, proto: Protocol, port: Optional[int]) -> bool:
        if self.protocol == "any" or proto == "any" or self.protocol == proto:
            if port is None or self.protocol == "icmp":
                return True
            for s, e in self.port_ranges():
                if s <= port <= e:
                    return True
        return False


@dataclass(slots=True)
class ServiceGroup:
    name: str
    members: List[str]  # names of ServiceObject or inline tokens "tcp:80-90", "udp:any"

    def expand(self, svc_map: Dict[str, ServiceObject]) -> List[ServiceObject]:
        res: List[ServiceObject] = []
        for m in self.members:
            if ":" in m and _norm_name(m.split(":")[0]) in {"tcp", "udp", "icmp", "any"}:
                pr, rest = m.split(":", 1)
                res.append(ServiceObject(name=m, protocol=pr.lower(), ports=[rest]))
            else:
                key = _norm_name(m)
                if key in svc_map:
                    res.append(svc_map[key])
                else:
                    # fallback plain token -> tcp
                    res.append(ServiceObject(name=m, protocol="tcp", ports=[m]))
        return res


# -----------------------------------------------------------------------------
# Time window
# -----------------------------------------------------------------------------

_DOW = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

@dataclass(slots=True)
class TimeWindow:
    days: List[str]  # e.g. ["mon","tue","*"] or ["*"]
    start: Optional[str] = None  # "HH:MM"
    end: Optional[str] = None    # "HH:MM", supports overnight intervals (e.g., 22:00-06:00)

    def active(self, dt: Optional[datetime] = None) -> bool:
        dt = dt or datetime.utcnow()
        day = ["mon","tue","wed","thu","fri","sat","sun"][dt.weekday()]
        if self.days and "*" not in self.days and day not in self.days:
            return False
        if not self.start and not self.end:
            return True
        # parse HH:MM
        def _p(x: Optional[str]) -> Optional[dtime]:
            if not x:
                return None
            h, m = [int(z) for z in x.split(":")]
            return dtime(hour=h, minute=m)
        s = _p(self.start)
        e = _p(self.end)
        t = dtime(hour=dt.hour, minute=dt.minute)
        if s and e:
            if s <= e:
                return s <= t <= e
            # overnight
            return t >= s or t <= e
        if s and not e:
            return t >= s
        if e and not s:
            return t <= e
        return True


# -----------------------------------------------------------------------------
# Rule and Policy
# -----------------------------------------------------------------------------

@dataclass(slots=True)
class Rule:
    name: str
    direction: Direction
    src_addrs: List[str]            # names of AddressObject/Group or inline
    dst_addrs: List[str]            # names of AddressObject/Group or inline
    services: List[str]             # names of ServiceObject/Group or inline "tcp:80"
    action: Action
    log: bool = False
    disabled: bool = False
    description: Optional[str] = None
    time_window: Optional[TimeWindow] = None
    tags: Dict[str, Any] = field(default_factory=dict)

    def signature(self) -> str:
        base = {
            "name": self.name,
            "direction": self.direction,
            "src": sorted(self.src_addrs),
            "dst": sorted(self.dst_addrs),
            "services": sorted(self.services),
            "action": self.action,
            "log": self.log,
            "disabled": self.disabled,
            "time": dataclasses.asdict(self.time_window) if self.time_window else None,
        }
        return _sha(base)


@dataclass(slots=True)
class Policy:
    name: str
    default_action: Action = "deny"
    address_objects: Dict[str, AddressObject] = field(default_factory=dict)   # key is normalized name
    address_groups: Dict[str, AddressGroup] = field(default_factory=dict)
    service_objects: Dict[str, ServiceObject] = field(default_factory=dict)
    service_groups: Dict[str, ServiceGroup] = field(default_factory=dict)
    rules: List[Rule] = field(default_factory=list)

    # ---------- Resolution ----------

    def _resolve_addrs(self, tokens: List[str]) -> AddressObject:
        vals: List[str] = []
        for t in tokens:
            key = _norm_name(t)
            if key in self.address_objects:
                vals.extend(self.address_objects[key].values)
            elif key in self.address_groups:
                ao = self.address_groups[key].expand(self.address_objects)
                vals.extend(ao.values)
            else:
                vals.append(t)
        return AddressObject(name="__resolved__", values=vals)

    def _resolve_svcs(self, tokens: List[str]) -> List[ServiceObject]:
        res: List[ServiceObject] = []
        for t in tokens:
            key = _norm_name(t)
            if key in self.service_objects:
                res.append(self.service_objects[key])
            elif key in self.service_groups:
                res.extend(self.service_groups[key].expand(self.service_objects))
            else:
                # inline "tcp:80"
                if ":" in t:
                    pr, rest = t.split(":", 1)
                    res.append(ServiceObject(name=t, protocol=pr.lower(), ports=[rest]))
                else:
                    # default tcp for naked port name or IANA mapping name
                    res.append(ServiceObject(name=t, protocol="tcp", ports=[t]))
        return res

    # ---------- Validation ----------

    def validate(self) -> List[str]:
        errors: List[str] = []
        # address group references
        for g in self.address_groups.values():
            for m in g.members:
                k = _norm_name(m)
                if k not in self.address_objects and not re.search(r"[/:\-]|any", m, re.I):
                    # not object and not inline CIDR/IP/range/any
                    errors.append(f"address group '{g.name}' member '{m}' not resolvable")
        # service group references
        for g in self.service_groups.values():
            for m in g.members:
                k = _norm_name(m.split(":")[0]) if ":" in m else _norm_name(m)
                if ":" in m:
                    proto = m.split(":", 1)[0].lower()
                    if proto not in {"tcp","udp","icmp","any"}:
                        errors.append(f"service group '{g.name}' member '{m}' has invalid protocol")
                elif k not in self.service_objects and not re.search(r"[:\-]|any|\d|,", m, re.I) and m.lower() not in _IANA_PORTS:
                    errors.append(f"service group '{g.name}' member '{m}' not resolvable")
        # rule refs
        for r in self.rules:
            if r.direction not in ("ingress", "egress"):
                errors.append(f"rule '{r.name}' invalid direction")
            try:
                self._resolve_addrs(r.src_addrs)
                self._resolve_addrs(r.dst_addrs)
                self._resolve_svcs(r.services)
            except Exception as e:
                errors.append(f"rule '{r.name}' resolution error: {e}")
        return errors

    # ---------- Shadow and conflict analysis ----------

    def analyze(self) -> Dict[str, List[str]]:
        notes: Dict[str, List[str]] = {"shadowed": [], "conflicts": [], "warnings": []}

        def _svc_overlap(a: ServiceObject, b: ServiceObject) -> bool:
            # any protocol overlaps with any, or same protocol
            if a.protocol == "any" or b.protocol == "any" or a.protocol == b.protocol:
                if a.protocol == "icmp" or b.protocol == "icmp":
                    return a.protocol == b.protocol or "any" in (a.protocol, b.protocol)
                for s1, e1 in a.port_ranges():
                    for s2, e2 in b.port_ranges():
                        if not (e1 < s2 or e2 < s1):
                            return True
            return False

        def _addr_overlap(A: AddressObject, B: AddressObject) -> bool:
            for na in A.networks():
                for nb in B.networks():
                    if na.version == nb.version and (na.overlaps(nb) or nb.overlaps(na)):
                        return True
            return False

        # First-match semantics: if earlier rule fully covers later rule's match set
        # we declare later rule shadowed; for partial overlap and different action -> conflict.
        for i, r1 in enumerate(self.rules):
            if r1.disabled:
                continue
            a1s = self._resolve_addrs(r1.src_addrs)
            a1d = self._resolve_addrs(r1.dst_addrs)
            s1s = self._resolve_svcs(r1.services)
            for j in range(i + 1, len(self.rules)):
                r2 = self.rules[j]
                if r2.disabled or r1.direction != r2.direction:
                    continue
                a2s = self._resolve_addrs(r2.src_addrs)
                a2d = self._resolve_addrs(r2.dst_addrs)
                s2s = self._resolve_svcs(r2.services)
                # Check overlaps existence
                if not _addr_overlap(a1s, a2s) or not _addr_overlap(a1d, a2d):
                    continue
                if not any(_svc_overlap(x, y) for x in s1s for y in s2s):
                    continue
                if r1.action == r2.action:
                    # potential shadow: if r1 is broader or equal in all dimensions
                    if self._covers(a1s, a2s) and self._covers(a1d, a2d) and self._svc_covers(s1s, s2s):
                        notes["shadowed"].append(f"rule '{r2.name}' shadowed by '{r1.name}'")
                else:
                    # partial or total conflict
                    notes["conflicts"].append(f"rule '{r2.name}' conflicts with earlier '{r1.name}'")
        return notes

    def _covers(self, A: AddressObject, B: AddressObject) -> bool:
        # return True if union(A) covers union(B)
        bnets = B.networks()
        for nb in bnets:
            if not any(na.version == nb.version and (nb.subnet_of(na) or na == nb) for na in A.networks()):
                return False
        return True

    def _svc_covers(self, A: List[ServiceObject], B: List[ServiceObject]) -> bool:
        # A covers B if for every b in B there exists a in A that covers protocol and ports
        for b in B:
            ok = False
            for a in A:
                if a.protocol in ("any", b.protocol) or b.protocol in ("any", a.protocol):
                    if a.protocol == "icmp" or b.protocol == "icmp":
                        ok = (a.protocol == "any" or a.protocol == "icmp") and (b.protocol in ("icmp","any"))
                    else:
                        # ports
                        for s2, e2 in b.port_ranges():
                            if any(s1 <= s2 and e2 <= e1 for s1, e1 in a.port_ranges()):
                                ok = True
                                break
                if ok:
                    break
            if not ok:
                return False
        return True

    # ---------- Simulation ----------

    def evaluate_packet(
        self,
        direction: Direction,
        src_ip: str,
        dst_ip: str,
        protocol: Protocol,
        dst_port: Optional[int] = None,
        when: Optional[datetime] = None,
    ) -> Tuple[Action, Optional[str]]:
        sip = ipaddress.ip_address(src_ip)
        dip = ipaddress.ip_address(dst_ip)
        when = when or datetime.utcnow()

        for r in self.rules:
            if r.disabled or r.direction != direction:
                continue
            if r.time_window and not r.time_window.active(when):
                continue
            sa = self._resolve_addrs(r.src_addrs)
            da = self._resolve_addrs(r.dst_addrs)
            if not sa.contains_ip(sip) or not da.contains_ip(dip):
                continue
            for svc in self._resolve_svcs(r.services):
                if svc.matches(protocol, dst_port):
                    return r.action, r.name
        return self.default_action, None

    # ---------- Exporters ----------

    def export_nftables(self, inet_table: str = "filter") -> str:
        """
        Generate nftables rules (inet table) for INPUT/OUTPUT chains with counters and logging.
        """
        lines: List[str] = []
        lines.append(f"table inet {inet_table} {{")
        lines.append("  chain INPUT { type filter hook input priority 0; policy drop; }")
        lines.append("  chain OUTPUT { type filter hook output priority 0; policy drop; }")
        # Build rule lines
        for r in self.rules:
            if r.disabled:
                continue
            chain = "INPUT" if r.direction == "ingress" else "OUTPUT"
            # addresses
            src = self._resolve_addrs(r.src_addrs).networks()
            dst = self._resolve_addrs(r.dst_addrs).networks()
            svcs = self._resolve_svcs(r.services)
            # For simplicity, emit one rule per service and address combo
            for s in svcs:
                proto = s.protocol if s.protocol != "any" else "ip"
                port_expr = ""
                if s.protocol in ("tcp", "udp"):
                    rngs = s.port_ranges()
                    if len(rngs) == 1 and rngs[0] == (0, 65535):
                        port_expr = ""
                    else:
                        parts = []
                        for a, b in rngs:
                            if a == b:
                                parts.append(str(a))
                            else:
                                parts.append(f"{a}-{b}")
                        port_expr = f" dport {{ {', '.join(parts)} }}"
                # addresses emit
                for s_net in src:
                    for d_net in dst:
                        addr_expr = f"ip saddr {s_net} ip daddr {d_net}" if s_net.version == 4 else f"ip6 saddr {s_net} ip6 daddr {d_net}"
                        act = "accept" if r.action == "allow" else ("reject" if r.action == "reject" else "drop")
                        log = " log prefix \"fw:{}\"".format(r.name[:40]) if r.log else ""
                        lines.append(f"  chain {chain} {{ {proto} {addr_expr}{port_expr} counter{log} {act}; }}")
        # Default policy is enforced by chain policy; we set drop by default and append accept at end if needed
        if self.default_action == "allow":
            lines.append("  chain INPUT { policy accept; }")
            lines.append("  chain OUTPUT { policy accept; }")
        lines.append("}")
        return "\n".join(lines)

    def export_iptables(self, table: str = "filter") -> List[str]:
        """
        Generate iptables(-legacy) commands list. Caller decides how to apply.
        """
        cmds: List[str] = []
        # Flush and set default
        policy = "ACCEPT" if self.default_action == "allow" else "DROP"
        cmds += [f"iptables -t {table} -P INPUT {policy}", f"iptables -t {table} -P OUTPUT {policy}"]
        cmds += [f"iptables -t {table} -F INPUT", f"iptables -t {table} -F OUTPUT"]
        for r in self.rules:
            if r.disabled:
                continue
            chain = "INPUT" if r.direction == "ingress" else "OUTPUT"
            act = "ACCEPT" if r.action == "allow" else ("REJECT" if r.action == "reject" else "DROP")
            src = self._resolve_addrs(r.src_addrs).networks()
            dst = self._resolve_addrs(r.dst_addrs).networks()
            svcs = self._resolve_svcs(r.services)
            for s in svcs:
                proto = "all" if s.protocol == "any" else s.protocol
                for s_net in src:
                    for d_net in dst:
                        base = f"iptables -t {table} -A {chain} -p {proto} -s {s_net} -d {d_net}"
                        if s.protocol in ("tcp", "udp"):
                            rngs = s.port_ranges()
                            if len(rngs) == 1 and rngs[0] == (0, 65535):
                                port = ""
                                cmd = f"{base}{port} -m comment --comment \"{r.name}\" -j {act}"
                                if r.log:
                                    cmds.append(f"{base} -m limit --limit 5/second -j LOG --log-prefix \"fw:{r.name[:32]} \"")
                                cmds.append(cmd)
                            else:
                                for a, b in rngs:
                                    port = f" --dport {a}" if a == b else f" -m multiport --dports {a}:{b}"
                                    cmd = f"{base}{port} -m comment --comment \"{r.name}\" -j {act}"
                                    if r.log:
                                        cmds.append(f"{base}{port} -m limit --limit 5/second -j LOG --log-prefix \"fw:{r.name[:32]} \"")
                                    cmds.append(cmd)
                        else:
                            cmd = f"{base} -m comment --comment \"{r.name}\" -j {act}"
                            if r.log:
                                cmds.append(f"{base} -m limit --limit 5/second -j LOG --log-prefix \"fw:{r.name[:32]} \"")
                            cmds.append(cmd)
        return cmds

    def export_aws_sg(self, vpc_id: str, group_name: str, description: str = "") -> Dict[str, Any]:
        """
        Build AWS Security Group-like structure with IpPermissions(Ingress/Egress).
        """
        def _ip_perm(direction: Direction) -> List[Dict[str, Any]]:
            perms: List[Dict[str, Any]] = []
            for r in self.rules:
                if r.disabled or r.direction != direction or r.action != "allow":
                    continue
                for svc in self._resolve_svcs(r.services):
                    if svc.protocol == "icmp":
                        ipproto = "icmp"
                        from_p = to_p = -1
                    elif svc.protocol == "any":
                        ipproto = "-1"
                        from_p = to_p = None
                    else:
                        ipproto = svc.protocol
                        rngs = svc.port_ranges()
                        if len(rngs) == 1 and rngs[0] == (0, 65535):
                            from_p = 0
                            to_p = 65535
                        else:
                            # AWS SG does not support multiple discrete ranges per permission; split
                            for a, b in rngs:
                                cidrs, cidrs6 = self._cidr_pairs(r)
                                perms.append({
                                    "IpProtocol": ipproto,
                                    "FromPort": a,
                                    "ToPort": b,
                                    "IpRanges": [{"CidrIp": c, "Description": r.name} for c in cidrs],
                                    "Ipv6Ranges": [{"CidrIpv6": c, "Description": r.name} for c in cidrs6],
                                })
                            continue
                    cidrs, cidrs6 = self._cidr_pairs(r)
                    perms.append({
                        "IpProtocol": ipproto,
                        "FromPort": from_p,
                        "ToPort": to_p,
                        "IpRanges": [{"CidrIp": c, "Description": r.name} for c in cidrs],
                        "Ipv6Ranges": [{"CidrIpv6": c, "Description": r.name} for c in cidrs6],
                    })
            return perms

        return {
            "VpcId": vpc_id,
            "GroupName": group_name,
            "Description": description or self.name,
            "IpPermissions": _ip_perm("ingress"),
            "IpPermissionsEgress": _ip_perm("egress"),
        }

    def export_azure_nsg(self, nsg_name: str, resource_group: str) -> Dict[str, Any]:
        """
        Build Azure NSG-like structure with securityRules.
        """
        def _addr_pair(r: Rule) -> Tuple[List[str], List[str]]:
            src = self._resolve_addrs(r.src_addrs).networks()
            dst = self._resolve_addrs(r.dst_addrs).networks()
            src4 = [str(n) for n in src if isinstance(n, ipaddress.IPv4Network)]
            src6 = [str(n) for n in src if isinstance(n, ipaddress.IPv6Network)]
            dst4 = [str(n) for n in dst if isinstance(n, ipaddress.IPv4Network)]
            dst6 = [str(n) for n in dst if isinstance(n, ipaddress.IPv6Network)]
            return src4 + src6, dst4 + dst6

        rules_json: List[Dict[str, Any]] = []
        priority = 100
        for r in self.rules:
            if r.disabled:
                continue
            for svc in self._resolve_svcs(r.services):
                proto = "*" if svc.protocol == "any" else svc.protocol.upper()
                ports: List[str] = []
                if svc.protocol in ("tcp", "udp"):
                    for a, b in svc.port_ranges():
                        ports.append(str(a) if a == b else f"{a}-{b}")
                else:
                    ports = ["*"]
                srcs, dsts = _addr_pair(r)
                rules_json.append({
                    "name": _norm_name(r.name)[:60],
                    "properties": {
                        "priority": priority,
                        "direction": "Inbound" if r.direction == "ingress" else "Outbound",
                        "access": "Allow" if r.action == "allow" else "Deny",
                        "protocol": proto,
                        "sourcePortRange": "*",
                        "destinationPortRanges": ports,
                        "sourceAddressPrefixes": srcs or ["*"],
                        "destinationAddressPrefixes": dsts or ["*"],
                        "description": r.description or "",
                    },
                })
                priority += 10
        return {"name": nsg_name, "resourceGroup": resource_group, "properties": {"securityRules": rules_json}}

    def _cidr_pairs(self, r: Rule) -> Tuple[List[str], List[str]]:
        src = self._resolve_addrs(r.src_addrs).networks()
        dst = self._resolve_addrs(r.dst_addrs).networks()
        # AWS SG requires source only for ingress and destination only for egress; for simplicity use counterpart as 0.0.0.0/0
        nets = src if r.direction == "ingress" else dst
        v4 = [str(n) for n in nets if isinstance(n, ipaddress.IPv4Network)]
        v6 = [str(n) for n in nets if isinstance(n, ipaddress.IPv6Network)]
        if not v4 and not v6:
            v4 = ["0.0.0.0/0"]
        return v4, v6

    # ---------- Diff ----------

    def diff(self, other: Policy) -> Dict[str, List[Rule]]:
        """
        Diff current policy to other (desired). Returns rules to add/remove/update
        by comparing signatures and names.
        """
        mine = {r.name: r for r in self.rules}
        yours = {r.name: r for r in other.rules}
        to_add: List[Rule] = []
        to_remove: List[Rule] = []
        to_update: List[Rule] = []

        for name, r in yours.items():
            if name not in mine:
                to_add.append(r)
            else:
                if r.signature() != mine[name].signature():
                    to_update.append(r)
        for name in mine:
            if name not in yours:
                to_remove.append(mine[name])
        return {"add": to_add, "remove": to_remove, "update": to_update}


# -----------------------------------------------------------------------------
# Loading and serialization
# -----------------------------------------------------------------------------

def load_policy(text_or_path: str) -> Policy:
    """
    Load policy from JSON or YAML. If string looks like a path, read file.
    """
    raw: Any
    try:
        import os
        if "\n" not in text_or_path and len(text_or_path) < 4096 and os.path.exists(text_or_path):
            with open(text_or_path, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = text_or_path
        try:
            raw = json.loads(content)
        except json.JSONDecodeError:
            if not _HAS_YAML:
                raise RuntimeError("YAML not available; install PyYAML or provide JSON")
            raw = yaml.safe_load(content)  # type: ignore
    except Exception as e:
        raise RuntimeError(f"failed to load policy: {e}")

    return parse_policy(raw)


def parse_policy(obj: Dict[str, Any]) -> Policy:
    """
    Parse dict into Policy with validation.
    """
    name = obj.get("name") or "policy"
    default_action: Action = obj.get("default_action", "deny")
    addr_objs: Dict[str, AddressObject] = {}
    for ao in obj.get("address_objects", []) or []:
        ao_name = _norm_name(ao["name"])
        addr_objs[ao_name] = AddressObject(name=ao["name"], values=list(ao.get("values", [])))
    addr_groups: Dict[str, AddressGroup] = {}
    for ag in obj.get("address_groups", []) or []:
        ag_name = _norm_name(ag["name"])
        addr_groups[ag_name] = AddressGroup(name=ag["name"], members=list(ag.get("members", [])))
    svc_objs: Dict[str, ServiceObject] = {}
    for so in obj.get("service_objects", []) or []:
        so_name = _norm_name(so["name"])
        svc_objs[so_name] = ServiceObject(
            name=so["name"],
            protocol=str(so.get("protocol", "tcp")).lower(),
            ports=[str(p) for p in (so.get("ports") or ["any"])],
        )
    svc_groups: Dict[str, ServiceGroup] = {}
    for sg in obj.get("service_groups", []) or []:
        sg_name = _norm_name(sg["name"])
        svc_groups[sg_name] = ServiceGroup(name=sg["name"], members=list(sg.get("members", [])))

    rules: List[Rule] = []
    for r in obj.get("rules", []) or []:
        tw = r.get("time_window")
        window = None
        if tw:
            window = TimeWindow(
                days=[d.lower() for d in (tw.get("days") or ["*"])],
                start=tw.get("start"),
                end=tw.get("end"),
            )
        rules.append(Rule(
            name=r["name"],
            direction=str(r.get("direction", "ingress")).lower(),  # type: ignore
            src_addrs=list(r.get("src", [])),
            dst_addrs=list(r.get("dst", [])),
            services=list(r.get("services", [])),
            action=str(r.get("action", "deny")).lower(),  # type: ignore
            log=bool(r.get("log", False)),
            disabled=bool(r.get("disabled", False)),
            description=r.get("description"),
            time_window=window,
            tags=dict(r.get("tags", {})),
        ))

    pol = Policy(
        name=name,
        default_action=default_action,
        address_objects=addr_objs,
        address_groups=addr_groups,
        service_objects=svc_objs,
        service_groups=svc_groups,
        rules=rules,
    )
    errs = pol.validate()
    if errs:
        raise RuntimeError("policy validation failed: " + "; ".join(errs))
    return pol


# -----------------------------------------------------------------------------
# Example usage (manual test)
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    example = {
        "name": "example",
        "default_action": "deny",
        "address_objects": [
            {"name": "corp_net", "values": ["10.0.0.0/8", "192.168.0.0/16"]},
            {"name": "any", "values": ["any"]},
        ],
        "service_objects": [
            {"name": "web", "protocol": "tcp", "ports": ["80,443"]},
            {"name": "dns", "protocol": "udp", "ports": ["53"]},
        ],
        "service_groups": [
            {"name": "common_web", "members": ["web"]},
        ],
        "rules": [
            {
                "name": "allow_web_out",
                "direction": "egress",
                "src": ["corp_net"],
                "dst": ["any"],
                "services": ["common_web"],
                "action": "allow",
                "log": True,
            },
            {
                "name": "allow_dns_out",
                "direction": "egress",
                "src": ["corp_net"],
                "dst": ["any"],
                "services": ["dns"],
                "action": "allow",
            },
            {
                "name": "deny_all_in",
                "direction": "ingress",
                "src": ["any"],
                "dst": ["corp_net"],
                "services": ["any:any"],
                "action": "deny",
                "log": True,
            },
        ],
    }

    pol = parse_policy(example)
    print("Policy:", pol.name)
    print("Analyze:", json.dumps(pol.analyze(), indent=2))
    print("Simulate egress 10.1.2.3 -> 1.2.3.4 tcp/443:", pol.evaluate_packet("egress", "10.1.2.3", "1.2.3.4", "tcp", 443))
    print("iptables:")
    for c in pol.export_iptables():
        print(c)
    print("nftables:")
    print(pol.export_nftables())
    print("aws sg:")
    print(json.dumps(pol.export_aws_sg("vpc-123", "sg-example"), indent=2))
    print("azure nsg:")
    print(json.dumps(pol.export_azure_nsg("nsg-example", "rg-demo"), indent=2))
