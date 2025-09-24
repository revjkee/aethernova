# cybersecurity-core/cybersecurity/zero_trust/microsegmentation.py
"""
Zero Trust Microsegmentation Engine (stdlib only).

Функции модуля:
- Модели активов (Endpoint), портов/протоколов, селекторов (labels + CIDR).
- Intent-политика и компиляция в детерминированные L3/L4 правила (allow/deny) с приоритетами.
- Движок принятия решений для конкретного потока (src,dst,proto,port) с объяснением (explain).
- Симуляция связности между наборами Endpoints и выявление «теневых» (shadowed) правил/перекрытий.
- Канонизация и минимизация правил (слияние порт-диапазонов/протоколов).
- Генерация ACL для iptables и nftables (для дальнейшего конфигурирования агентов).
- Дифф двух версий политики (added/removed/changed).
- Аудит решений и стабильные хэши правил.
- Мультиарендность и «зоны доверия» (trust zones).

Ограничения:
- L7/HTTP awareness не реализован умышленно; интерфейсы оставлены для расширения.
- Генерация ACL предполагает статические IP/CIDR отборы (селекторы по меткам транслируются через текущее множество endpoints).
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


# --------------------------------------------------------------------------------------
# Базовые типы
# --------------------------------------------------------------------------------------

class Protocol(str, Enum):
    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Direction(str, Enum):
    INGRESS = "ingress"
    EGRESS = "egress"
    BIDIRECTIONAL = "bidir"


@dataclass(frozen=True)
class PortRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if not (0 <= self.start <= 65535 and 0 <= self.end <= 65535 and self.start <= self.end):
            raise ValueError("invalid port range")

    @staticmethod
    def from_list(values: Iterable[int]) -> List["PortRange"]:
        s = sorted(set(int(v) for v in values if 0 <= int(v) <= 65535))
        if not s:
            return []
        out: List[PortRange] = []
        a = b = s[0]
        for v in s[1:]:
            if v == b + 1:
                b = v
            else:
                out.append(PortRange(a, b))
                a = b = v
        out.append(PortRange(a, b))
        return out

    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end

    def to_string(self) -> str:
        return f"{self.start}" if self.start == self.end else f"{self.start}:{self.end}"


@dataclass(frozen=True)
class LabelSelector:
    """Простой селектор: точные совпадения по меткам и отрицания, плюс список CIDR."""
    match: Mapping[str, Set[str]] = field(default_factory=dict)
    not_match: Mapping[str, Set[str]] = field(default_factory=dict)
    cidrs: Tuple[str, ...] = field(default_factory=tuple)  # список CIDR для дополнительной фильтрации IP

    def matches_labels(self, labels: Mapping[str, str]) -> bool:
        for k, allowed in self.match.items():
            v = labels.get(k)
            if v is None or v not in allowed:
                return False
        for k, denied in self.not_match.items():
            v = labels.get(k)
            if v is not None and v in denied:
                return False
        return True

    def matches_ip(self, ip: str) -> bool:
        if not self.cidrs:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for c in self.cidrs:
            try:
                if addr in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def fingerprint(self) -> str:
        payload = {
            "match": {k: sorted(v) for k, v in sorted(self.match.items())},
            "not_match": {k: sorted(v) for k, v in sorted(self.not_match.items())},
            "cidrs": sorted(self.cidrs),
        }
        return _sha256(payload)


@dataclass(frozen=True)
class Endpoint:
    id: str
    tenant_id: str
    ip_addrs: Tuple[str, ...]
    labels: Mapping[str, str]
    trust_zone: str = "default"

    def ips_valid(self) -> Tuple[str, ...]:
        out = []
        for ip in self.ip_addrs:
            try:
                ipaddress.ip_address(ip)
                out.append(ip)
            except ValueError:
                continue
        return tuple(out)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    tenant_id: str
    priority: int
    action: Action
    direction: Direction
    src: LabelSelector
    dst: LabelSelector
    protocols: Tuple[Protocol, ...] = (Protocol.TCP, Protocol.UDP)
    ports: Tuple[PortRange, ...] = tuple()
    description: str = ""
    enabled: bool = True
    trust_zones: Tuple[Tuple[str, str], ...] = tuple()  # (src_zone, dst_zone) ограничения, если заданы
    version: str = "1.0.0"

    def matches_flow(self, flow: "Flow", src_ep: Endpoint, dst_ep: Endpoint) -> bool:
        if not self.enabled:
            return False
        if self.direction == Direction.INGRESS and flow.direction != Direction.INGRESS:
            return False
        if self.direction == Direction.EGRESS and flow.direction != Direction.EGRESS:
            return False
        if self.trust_zones:
            if not any(sz == src_ep.trust_zone and dz == dst_ep.trust_zone for sz, dz in self.trust_zones):
                return False
        if not self.src.matches_labels(src_ep.labels) or not self.dst.matches_labels(dst_ep.labels):
            return False
        if not any(self.src.matches_ip(ip) for ip in src_ep.ips_valid()):
            return False
        if not any(self.dst.matches_ip(ip) for ip in dst_ep.ips_valid()):
            return False
        if Protocol.ANY not in self.protocols and flow.protocol not in self.protocols:
            return False
        if self.ports:
            return any(pr.contains(flow.dport) for pr in self.ports)
        # если порт не указан в правиле — трактуем как любой (для ICMP и т.п.)
        return True

    def key_without_priority(self) -> Tuple:
        return (
            self.tenant_id,
            self.action.value,
            self.direction.value,
            self.src.fingerprint(),
            self.dst.fingerprint(),
            tuple(p.value for p in self.protocols),
            tuple((pr.start, pr.end) for pr in self.ports),
            self.trust_zones,
        )

    def fingerprint(self) -> str:
        payload = {
            "rule_id": self.rule_id,
            "tenant": self.tenant_id,
            "priority": self.priority,
            "action": self.action.value,
            "direction": self.direction.value,
            "src": self.src.fingerprint(),
            "dst": self.dst.fingerprint(),
            "protocols": [p.value for p in self.protocols],
            "ports": [(p.start, p.end) for p in self.ports],
            "tz": list(self.trust_zones),
            "version": self.version,
        }
        return _sha256(payload)


@dataclass(frozen=True)
class Intent:
    """Высокоуровневый intent: «разрешить traffic от A к B на список портов/протоколов»."""
    intent_id: str
    tenant_id: str
    name: str
    src: LabelSelector
    dst: LabelSelector
    allow_protocols: Tuple[Protocol, ...]
    allow_ports: Tuple[PortRange, ...]
    direction: Direction = Direction.BIDIRECTIONAL
    trust_zones: Tuple[Tuple[str, str], ...] = tuple()
    description: str = ""


@dataclass(frozen=True)
class Flow:
    """Запрос на принятие решения."""
    tenant_id: str
    src_id: str
    dst_id: str
    protocol: Protocol
    dport: int
    direction: Direction  # INGRESS: dst — это защищаемый хост; EGRESS — исходящий


@dataclass
class Decision:
    allowed: bool
    action: Action
    rule_id: Optional[str]
    matched_priority: Optional[int]
    reason: str
    explain: Dict[str, Any]
    audited_at: float = field(default_factory=lambda: time.time())


# --------------------------------------------------------------------------------------
# Вспомогательные утилиты
# --------------------------------------------------------------------------------------

def _sha256(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _merge_port_ranges(ranges: Sequence[PortRange]) -> Tuple[PortRange, ...]:
    if not ranges:
        return tuple()
    srt = sorted(ranges, key=lambda r: (r.start, r.end))
    out: List[PortRange] = []
    cur = srt[0]
    for r in srt[1:]:
        if r.start <= cur.end + 1:
            cur = PortRange(cur.start, max(cur.end, r.end))
        else:
            out.append(cur)
            cur = r
    out.append(cur)
    return tuple(out)


# --------------------------------------------------------------------------------------
# Компилятор Intent -> Rules
# --------------------------------------------------------------------------------------

class Compiler:
    @staticmethod
    def intents_to_rules(intents: Sequence[Intent], base_priority: int = 1000, step: int = 10) -> List[Rule]:
        """
        Компилирует intents в ALLOW-правила, каждая сторона (uni/bidir).
        DENY-правила задаются отдельно политикой «по умолчанию: deny».
        """
        rules: List[Rule] = []
        pr = base_priority
        for it in intents:
            common = dict(
                tenant_id=it.tenant_id,
                src=it.src,
                dst=it.dst,
                protocols=it.allow_protocols,
                ports=_merge_port_ranges(it.allow_ports),
                trust_zones=it.trust_zones,
                description=f"intent:{it.name}",
            )
            # основной
            rules.append(Rule(
                rule_id=f"{it.intent_id}-ing",
                priority=pr,
                action=Action.ALLOW,
                direction=Direction.INGRESS,
                **common,
            ))
            pr += step
            rules.append(Rule(
                rule_id=f"{it.intent_id}-eg",
                priority=pr,
                action=Action.ALLOW,
                direction=Direction.EGRESS,
                **common,
            ))
            pr += step
            if it.direction == Direction.BIDIRECTIONAL:
                # симметричный (меняем src/dst)
                rules.append(Rule(
                    rule_id=f"{it.intent_id}-ing-rev",
                    priority=pr,
                    action=Action.ALLOW,
                    direction=Direction.INGRESS,
                    tenant_id=it.tenant_id,
                    src=it.dst, dst=it.src,
                    protocols=it.allow_protocols,
                    ports=_merge_port_ranges(it.allow_ports),
                    trust_zones=tuple((b, a) for (a, b) in it.trust_zones) if it.trust_zones else tuple(),
                    description=f"intent:{it.name}:reverse",
                ))
                pr += step
                rules.append(Rule(
                    rule_id=f"{it.intent_id}-eg-rev",
                    priority=pr,
                    action=Action.ALLOW,
                    direction=Direction.EGRESS,
                    tenant_id=it.tenant_id,
                    src=it.dst, dst=it.src,
                    protocols=it.allow_protocols,
                    ports=_merge_port_ranges(it.allow_ports),
                    trust_zones=tuple((b, a) for (a, b) in it.trust_zones) if it.trust_zones else tuple(),
                    description=f"intent:{it.name}:reverse",
                ))
                pr += step
        return rules


# --------------------------------------------------------------------------------------
# Политика и движок
# --------------------------------------------------------------------------------------

@dataclass
class Policy:
    tenant_id: str
    rules: List[Rule]
    default_action: Action = Action.DENY
    version: str = "1.0.0"

    def sorted_rules(self) -> List[Rule]:
        return sorted((r for r in self.rules if r.enabled), key=lambda r: (r.priority, r.rule_id))


class Engine:
    def __init__(self) -> None:
        self._audit_log: List[Decision] = []

    @staticmethod
    def _resolve(ep_index: Mapping[str, Endpoint], eid: str) -> Endpoint:
        if eid not in ep_index:
            raise KeyError(f"endpoint not found: {eid}")
        return ep_index[eid]

    def decide(self, policy: Policy, flow: Flow, endpoints: Mapping[str, Endpoint]) -> Decision:
        """Главный алгоритм принятия решения: первая по приоритету полная матча."""
        src = self._resolve(endpoints, flow.src_id)
        dst = self._resolve(endpoints, flow.dst_id)
        if src.tenant_id != policy.tenant_id or dst.tenant_id != policy.tenant_id or flow.tenant_id != policy.tenant_id:
            # Жёсткая изоляция арендаторов
            decision = Decision(
                allowed=False, action=Action.DENY, rule_id=None, matched_priority=None,
                reason="cross-tenant traffic denied", explain={"tenant_mismatch": True}
            )
            self._audit_log.append(decision)
            return decision

        for r in policy.sorted_rules():
            if r.matches_flow(flow, src, dst):
                allowed = (r.action == Action.ALLOW)
                decision = Decision(
                    allowed=allowed, action=r.action, rule_id=r.rule_id, matched_priority=r.priority,
                    reason="rule_matched",
                    explain={
                        "src": src.id, "dst": dst.id, "protocol": flow.protocol.value, "dport": flow.dport,
                        "direction": flow.direction.value, "rule": r.fingerprint(),
                    }
                )
                self._audit_log.append(decision)
                return decision

        # default
        decision = Decision(
            allowed=(policy.default_action == Action.ALLOW),
            action=policy.default_action, rule_id=None, matched_priority=None,
            reason="default_policy", explain={}
        )
        self._audit_log.append(decision)
        return decision

    def audit_log(self) -> List[Decision]:
        return list(self._audit_log)

    # ---- Аналитика политики ----

    @staticmethod
    def detect_shadowed_rules(policy: Policy, endpoints: Mapping[str, Endpoint]) -> List[Tuple[str, str]]:
        """
        Возвращает пары (shadowed_rule_id, overshadowing_rule_id) для правил, полностью перекрытых более приоритетными.
        Эвристика: сравнение селекторов и портов; требует конечного множества endpoints.
        """
        rules = policy.sorted_rules()
        result: List[Tuple[str, str]] = []

        def endpoints_for(sel: LabelSelector) -> Set[str]:
            ids = set()
            for e in endpoints.values():
                if e.tenant_id != policy.tenant_id:
                    continue
                if sel.matches_labels(e.labels) and any(sel.matches_ip(ip) for ip in e.ips_valid()):
                    ids.add(e.id)
            return ids

        cache_ep: Dict[str, Set[str]] = {}
        for i, r_low in enumerate(rules):
            if not r_low.enabled:
                continue
            src_ids_low = cache_ep.setdefault(r_low.src.fingerprint(), endpoints_for(r_low.src))
            dst_ids_low = cache_ep.setdefault(r_low.dst.fingerprint(), endpoints_for(r_low.dst))
            for r_high in rules[:i]:
                if r_low.action != r_high.action or r_low.direction != r_high.direction:
                    continue
                if set(r_low.protocols).issubset(set(r_high.protocols)) or Protocol.ANY in r_high.protocols:
                    # порты
                    ports_low = _merge_port_ranges(r_low.ports or (PortRange(0, 65535),))
                    ports_high = _merge_port_ranges(r_high.ports or (PortRange(0, 65535),))
                    covered_ports = all(any(h.start <= l.start and h.end >= l.end for h in ports_high) for l in ports_low)
                    if not covered_ports:
                        continue
                    # src/dst множества
                    src_ids_high = cache_ep.setdefault(r_high.src.fingerprint(), endpoints_for(r_high.src))
                    dst_ids_high = cache_ep.setdefault(r_high.dst.fingerprint(), endpoints_for(r_high.dst))
                    if src_ids_low.issubset(src_ids_high) and dst_ids_low.issubset(dst_ids_high):
                        result.append((r_low.rule_id, r_high.rule_id))
                        break
        return result

    @staticmethod
    def simulate_graph(policy: Policy, endpoints: Mapping[str, Endpoint], protocols: Sequence[Protocol], ports: Sequence[int]) -> Dict[str, Set[str]]:
        """
        Строит ориентированный граф «кто к кому может подключаться» (EGRESS -> INGRESS) по заданным протоколам/портам.
        """
        engine = Engine()
        graph: Dict[str, Set[str]] = {}
        eps = [e for e in endpoints.values() if e.tenant_id == policy.tenant_id]
        for s, d in itertools.permutations(eps, 2):
            for proto in protocols:
                for port in ports:
                    # EGRESS (s->d)
                    egress = Flow(policy.tenant_id, s.id, d.id, proto, port, Direction.EGRESS)
                    ingress = Flow(policy.tenant_id, s.id, d.id, proto, port, Direction.INGRESS)
                    if engine.decide(policy, egress, endpoints).allowed and engine.decide(policy, ingress, endpoints).allowed:
                        graph.setdefault(s.id, set()).add(d.id)
                        break
        return graph

    @staticmethod
    def diff_policies(old: Policy, new: Policy) -> Dict[str, Any]:
        old_map = {r.rule_id: r for r in old.rules}
        new_map = {r.rule_id: r for r in new.rules}
        added = [r.rule_id for r in new.rules if r.rule_id not in old_map]
        removed = [r.rule_id for r in old.rules if r.rule_id not in new_map]
        changed = [rid for rid in old_map.keys() & new_map.keys()
                   if old_map[rid].fingerprint() != new_map[rid].fingerprint()]
        return {"added": added, "removed": removed, "changed": changed}


# --------------------------------------------------------------------------------------
# Генерация ACL (iptables/nft)
# --------------------------------------------------------------------------------------

class ACLGenerator:
    @staticmethod
    def _expand_ips(sel: LabelSelector, endpoints: Mapping[str, Endpoint], tenant_id: str) -> List[str]:
        ips: Set[str] = set()
        for e in endpoints.values():
            if e.tenant_id != tenant_id:
                continue
            if sel.matches_labels(e.labels):
                for ip in e.ips_valid():
                    if sel.matches_ip(ip):
                        ips.add(ip)
        return sorted(ips)

    @staticmethod
    def to_iptables(policy: Policy, endpoints: Mapping[str, Endpoint], chain_ingress: str = "INPUT", chain_egress: str = "OUTPUT") -> List[str]:
        """
        Возвращает список команд iptables (таблица filter), реализующих текущую политику.
        Предполагается, что селекторы источника/назначения разворачиваются в наборы IP текущих endpoints.
        """
        lines: List[str] = []
        for r in policy.sorted_rules():
            if not r.enabled:
                continue
            src_ips = ACLGenerator._expand_ips(r.src, endpoints, policy.tenant_id)
            dst_ips = ACLGenerator._expand_ips(r.dst, endpoints, policy.tenant_id)
            if not src_ips or not dst_ips:
                continue
            targets = "ACCEPT" if r.action == Action.ALLOW else "DROP"
            chains = [chain_ingress] if r.direction in (Direction.INGRESS, Direction.BIDIRECTIONAL) else []
            if r.direction in (Direction.EGRESS, Direction.BIDIRECTIONAL):
                chains.append(chain_egress)
            prots = [p for p in r.protocols if p != Protocol.ANY] or [Protocol.TCP, Protocol.UDP]
            ports = r.ports or (PortRange(0, 65535),)
            for chain in chains:
                for proto in prots:
                    for pr in ports:
                        port_flag = f"--dport {pr.start}:{pr.end}" if pr.start != 0 or pr.end != 65535 else ""
                        for sip in src_ips:
                            for dip in dst_ips:
                                # INGRESS: пакет приходит на dip от sip; EGRESS: уходит от sip к dip
                                if chain == chain_ingress:
                                    line = f"iptables -A {chain} -p {proto.value} -s {sip} -d {dip} {port_flag} -j {targets}".strip()
                                else:
                                    line = f"iptables -A {chain} -p {proto.value} -s {sip} -d {dip} {port_flag} -j {targets}".strip()
                                lines.append(" ".join(line.split()))
        # Политика по умолчанию
        if policy.default_action == Action.DENY:
            lines.append(f"iptables -P {chain_ingress} DROP")
            lines.append(f"iptables -P {chain_egress} DROP")
        else:
            lines.append(f"iptables -P {chain_ingress} ACCEPT")
            lines.append(f"iptables -P {chain_egress} ACCEPT")
        return lines

    @staticmethod
    def to_nftables(policy: Policy, endpoints: Mapping[str, Endpoint], table: str = "inet filter") -> List[str]:
        """
        Возвращает nftables ruleset (простая форма).
        """
        lines: List[str] = [f"table {table}", "{", "    chain input { type filter hook input priority 0; }",
                            "    chain output { type filter hook output priority 0; }", "}"]
        # Реализация упрощённая: для продакшена предпочтителен stateful набор с наборами (sets).
        ipt = ACLGenerator.to_iptables(policy, endpoints)
        # Конвертер минимальный: выводим комментарий с соответствием
        return ["# nftables ruleset (skeleton); below iptables-equivalent for reference"] + [f"# {l}" for l in ipt]


# --------------------------------------------------------------------------------------
# Утилиты построения селекторов
# --------------------------------------------------------------------------------------

def make_selector(match: Mapping[str, Iterable[str]] | None = None,
                  not_match: Mapping[str, Iterable[str]] | None = None,
                  cidrs: Iterable[str] | None = None) -> LabelSelector:
    def toset(m: Mapping[str, Iterable[str]] | None) -> Dict[str, Set[str]]:
        return {k: set(map(str, v)) for k, v in (m or {}).items()}
    return LabelSelector(match=toset(match), not_match=toset(not_match), cidrs=tuple(cidrs or ()))

# --------------------------------------------------------------------------------------
# Пример использования (можно удалить в реальном деплое)
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    # Активы
    eps = {
        "web-1": Endpoint(id="web-1", tenant_id="acme", ip_addrs=("10.0.0.10",), labels={"app": "web", "tier": "frontend"}, trust_zone="dmz"),
        "web-2": Endpoint(id="web-2", tenant_id="acme", ip_addrs=("10.0.0.11",), labels={"app": "web", "tier": "frontend"}, trust_zone="dmz"),
        "db-1": Endpoint(id="db-1", tenant_id="acme", ip_addrs=("10.0.1.20",), labels={"app": "db", "tier": "backend"}, trust_zone="internal"),
        "admin": Endpoint(id="admin", tenant_id="acme", ip_addrs=("10.0.9.9",), labels={"role": "admin"}, trust_zone="admin"),
    }

    # Intents: веб к БД на 5432, админ к вебу по 22, зона ограничения dmz->internal
    intents = [
        Intent(
            intent_id="INT-DB-POSTGRES",
            tenant_id="acme",
            name="web to db postgres",
            src=make_selector(match={"app": ["web"]}),
            dst=make_selector(match={"app": ["db"]}),
            allow_protocols=(Protocol.TCP,),
            allow_ports=(PortRange(5432, 5432),),
            direction=Direction.BIDIRECTIONAL,
            trust_zones=(("dmz", "internal"),),
            description="Frontend talks to DB on 5432"
        ),
        Intent(
            intent_id="INT-SSH-ADMIN",
            tenant_id="acme",
            name="admin ssh to web",
            src=make_selector(match={"role": ["admin"]}),
            dst=make_selector(match={"app": ["web"]}),
            allow_protocols=(Protocol.TCP,),
            allow_ports=(PortRange(22, 22),),
            direction=Direction.BIDIRECTIONAL,
            trust_zones=(("admin", "dmz"),),
            description="Admin SSH"
        ),
    ]

    # Компиляция intents → rules + политика deny-by-default
    rules = Compiler.intents_to_rules(intents)
    pol = Policy(tenant_id="acme", rules=rules, default_action=Action.DENY, version="v1")

    eng = Engine()

    # Проверка конкретного потока
    flow = Flow(tenant_id="acme", src_id="web-1", dst_id="db-1", protocol=Protocol.TCP, dport=5432, direction=Direction.EGRESS)
    dec = eng.decide(pol, flow, eps)
    print("Decision:", dec.allowed, dec.action, dec.reason, dec.rule_id)

    # Граф связности
    graph = eng.simulate_graph(pol, eps, protocols=(Protocol.TCP,), ports=(22, 5432))
    print("Graph:", graph)

    # Теневые правила
    shadows = eng.detect_shadowed_rules(pol, eps)
    print("Shadowed:", shadows)

    # ACL (iptables)
    ipt = ACLGenerator.to_iptables(pol, eps)
    print("\n".join(ipt))
