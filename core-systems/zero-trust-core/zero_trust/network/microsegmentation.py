# zero-trust-core/zero_trust/network/microsegmentation.py
from __future__ import annotations

import ipaddress
import json
import re
import shlex
import textwrap
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


__all__ = [
    "Direction",
    "Action",
    "Protocol",
    "PortRange",
    "Selector",
    "Workload",
    "Rule",
    "Policy",
    "CompileTrace",
    "Plan",
    "MicrosegmentationCompiler",
]


# -----------------------------
# Модель домена
# -----------------------------

class Direction(str, Enum):
    INGRESS = "ingress"
    EGRESS = "egress"


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    SCTP = "sctp"
    ANY = "any"


@dataclass(frozen=True)
class PortRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if not (0 < self.start <= 65535 and 0 < self.end <= 65535 and self.start <= self.end):
            raise ValueError("invalid port range")

    @classmethod
    def single(cls, port: int) -> "PortRange":
        return cls(port, port)


@dataclass(frozen=True)
class Selector:
    """
    Простой селектор по меткам ворклоада: include и exclude.
    include={"env":{"prod","stage"}, "tier":{"web"}}
    exclude={"zone":{"dmz"}}
    Пустой селектор матчит всё.
    """
    include: Mapping[str, Set[str]] = field(default_factory=dict)
    exclude: Mapping[str, Set[str]] = field(default_factory=dict)

    def match(self, labels: Mapping[str, str]) -> bool:
        # include: все ключи должны совпасть хотя бы по одному значению
        for k, allowed in self.include.items():
            v = labels.get(k)
            if v is None or (allowed and v not in allowed):
                return False
        # exclude: если совпало — отвергаем
        for k, banned in self.exclude.items():
            v = labels.get(k)
            if v is not None and (not banned or v in banned):
                return False
        return True

    @staticmethod
    def from_query(q: str) -> "Selector":
        """
        Простейший разбор "k=v,k in (a,b),!k, k!=v".
        Не предназначен для сложных выражений; для них используйте явные include/exclude.
        """
        inc: Dict[str, Set[str]] = {}
        exc: Dict[str, Set[str]] = {}
        q = q.strip()
        if not q:
            return Selector()
        parts = [p.strip() for p in q.split(",") if p.strip()]
        for p in parts:
            if " in " in p:
                k, vals = p.split(" in ", 1)
                vals = vals.strip()
                m = re.match(r"^\((.*?)\)$", vals)
                if not m:
                    raise ValueError(f"invalid selector part: {p}")
                inc.setdefault(k.strip(), set()).update({x.strip() for x in m.group(1).split(",") if x.strip()})
            elif "!=" in p:
                k, v = [x.strip() for x in p.split("!=", 1)]
                exc.setdefault(k, set()).update({v})
            elif p.startswith("!"):
                exc.setdefault(p[1:].strip(), set()).update(set())
            elif "=" in p:
                k, v = [x.strip() for x in p.split("=", 1)]
                inc.setdefault(k, set()).update({v})
            else:
                # ключ без значения -> требуется наличие ключа
                inc.setdefault(p, set())
        return Selector(include=inc, exclude=exc)


@dataclass(frozen=True)
class Workload:
    """
    Представление защищаемого ворклоада/сервиса.
    ip_addrs — список L3 адресов (IPv4/IPv6), для k8s — Pod IP.
    """
    wid: str
    labels: Mapping[str, str]
    ip_addrs: Sequence[str]
    namespace: Optional[str] = None  # для k8s
    node: Optional[str] = None       # для k8s/VM
    spiffe_id: Optional[str] = None  # для id‑aware аудита

    def normalized_ips(self) -> List[str]:
        res: List[str] = []
        for s in self.ip_addrs:
            try:
                res.append(str(ipaddress.ip_address(s)))
            except ValueError:
                # допускаем CIDR при статической адресации
                try:
                    net = ipaddress.ip_network(s, strict=False)
                    # не разворачиваем сеть — используем как ipset/cidr
                    res.append(str(net))
                except ValueError:
                    raise ValueError(f"invalid ip or cidr in workload {self.wid}: {s}")
        return res


@dataclass(frozen=True)
class Rule:
    action: Action
    direction: Direction
    src: Selector = field(default_factory=Selector)
    dst: Selector = field(default_factory=Selector)
    protocols: Set[Protocol] = field(default_factory=lambda: {Protocol.ANY})
    ports: Sequence[PortRange] = field(default_factory=tuple)
    cidrs_src: Sequence[str] = field(default_factory=tuple)  # дополнительные внешние источники
    cidrs_dst: Sequence[str] = field(default_factory=tuple)  # доп. внешние назначения
    priority: int = 100                                      # меньше -> раньше
    description: str = ""
    log: bool = False

    def __post_init__(self) -> None:
        for c in list(self.cidrs_src) + list(self.cidrs_dst):
            ipaddress.ip_network(c, strict=False)  # валидация


@dataclass(frozen=True)
class Policy:
    default_action_ingress: Action = Action.DENY
    default_action_egress: Action = Action.DENY
    rules: Sequence[Rule] = field(default_factory=tuple)
    name: str = "default"

    def sorted_rules(self) -> List[Rule]:
        return sorted(self.rules, key=lambda r: (r.priority, r.action != Action.DENY))


# -----------------------------
# Трассировка/план
# -----------------------------

@dataclass
class CompileTrace:
    rule: Rule
    matched_src: Set[str] = field(default_factory=set)  # id ворклоадов
    matched_dst: Set[str] = field(default_factory=set)
    src_cidrs: Set[str] = field(default_factory=set)
    dst_cidrs: Set[str] = field(default_factory=set)


@dataclass
class Plan:
    """
    План применения для выбранного бэкенда.
    Для nftables/iptables — список команд оболочки.
    Для k8s — список YAML манифестов.
    """
    backend: str
    items: List[str]
    traces: List[CompileTrace] = field(default_factory=list)

    def dry_run(self) -> str:
        hdr = f"# Plan backend={self.backend}, items={len(self.items)}\n"
        return hdr + "\n".join(self.items)


# -----------------------------
# Компилятор
# -----------------------------

class MicrosegmentationCompiler:
    """
    Детерминированная компиляция политик в backend‑специфичные планы.
    """

    def __init__(self, tenant: str = "default", table: str = "zt") -> None:
        self.tenant = re.sub(r"[^a-zA-Z0-9_-]", "-", tenant)[:40] or "default"
        self.table = re.sub(r"[^a-zA-Z0-9_-]", "-", table)[:20] or "zt"

    # ---------- Основной pipeline ----------

    def compile(
        self,
        workloads: Sequence[Workload],
        policy: Policy,
        backend: str = "nftables",
        namespace: str = "default",
    ) -> Plan:
        """
        backend: "nftables" | "iptables" | "k8s"
        """
        graph, traces = self._build_graph(workloads, policy)
        if backend == "nftables":
            return self._compile_nftables(graph, workloads, policy, traces)
        if backend == "iptables":
            return self._compile_iptables(graph, workloads, policy, traces)
        if backend == "k8s":
            return self._compile_k8s(graph, workloads, policy, namespace, traces)
        raise ValueError("unknown backend")

    # ---------- Построение графа разрешений ----------

    def _build_graph(
        self, workloads: Sequence[Workload], policy: Policy
    ) -> Tuple[Dict[str, Dict[str, Dict[str, Set[int]]]], List[CompileTrace]]:
        """
        Возвращает:
          graph[direction]['src->dst'][protocol] = {порт...}
        Где src/dst — это workload.wid или специальный CIDR '<cidr>'.
        """
        wl_by_id: Dict[str, Workload] = {w.wid: w for w in workloads}
        traces: List[CompileTrace] = []
        graph: Dict[str, Dict[Tuple[str, str], Dict[str, Set[int]]]] = {
            Direction.INGRESS.value: {},
            Direction.EGRESS.value: {},
        }

        # Предрасчёт: соответствия селекторов ворклоадам
        def select_ids(sel: Selector) -> Set[str]:
            return {w.wid for w in workloads if sel.match(w.labels)}

        for rule in policy.sorted_rules():
            trace = CompileTrace(rule=rule)
            src_ids = select_ids(rule.src)
            dst_ids = select_ids(rule.dst)
            trace.matched_src = set(src_ids)
            trace.matched_dst = set(dst_ids)
            trace.src_cidrs = set(rule.cidrs_src)
            trace.dst_cidrs = set(rule.cidrs_dst)
            traces.append(trace)

            protos = self._expand_protocols(rule.protocols)
            ports = self._expand_ports(rule.ports)

            def add_edge(direction: Direction, s_key: str, d_key: str) -> None:
                g = graph[direction.value].setdefault((s_key, d_key), {})
                for pr in protos:
                    g.setdefault(pr, set()).update(ports if ports else {-1})  # -1 = любой порт

            if rule.direction is Direction.INGRESS:
                # src -> dst workloads, плюс внешние src CIDR -> dst workloads
                for dst in dst_ids:
                    for src in src_ids:
                        add_edge(Direction.INGRESS, src, dst)
                    for cidr in rule.cidrs_src:
                        add_edge(Direction.INGRESS, f"<{cidr}>", dst)
                # DENY в графе не накапливаем; применим позже при генерации default policy
            elif rule.direction is Direction.EGRESS:
                for src in src_ids:
                    for dst in dst_ids:
                        add_edge(Direction.EGRESS, src, dst)
                    for cidr in rule.cidrs_dst:
                        add_edge(Direction.EGRESS, src, f"<{cidr}>")

        # Валидируем IP адреса ворклоадов
        for w in workloads:
            for s in w.ip_addrs:
                ipaddress.ip_network(s if "/" in s else s + "/32", strict=False)

        return self._graph_to_strings(graph, wl_by_id), traces

    @staticmethod
    def _expand_protocols(protocols: Set[Protocol]) -> List[str]:
        if not protocols or Protocol.ANY in protocols:
            return ["tcp", "udp", "icmp", "sctp"]
        return sorted({p.value for p in protocols})

    @staticmethod
    def _expand_ports(ports: Sequence[PortRange]) -> List[int]:
        if not ports:
            return []
        res: Set[int] = set()
        for pr in ports:
            res.update(range(pr.start, pr.end + 1))
        return sorted(res)

    @staticmethod
    def _graph_to_strings(
        graph: Dict[str, Dict[Tuple[str, str], Dict[str, Set[int]]]],
        wl_by_id: Mapping[str, Workload],
    ) -> Dict[str, Dict[Tuple[str, str], Dict[str, Set[int]]]]:
        """
        Преобразует src/dst из идентификаторов ворклоадов в IP/сетевые строки.
        """
        result: Dict[str, Dict[Tuple[str, str], Dict[str, Set[int]]]] = {
            Direction.INGRESS.value: {},
            Direction.EGRESS.value: {},
        }
        for direction, edges in graph.items():
            for (src, dst), proto_ports in edges.items():
                src_ips = MicrosegmentationCompiler._expand_endpoint(src, wl_by_id)
                dst_ips = MicrosegmentationCompiler._expand_endpoint(dst, wl_by_id)
                for s in src_ips:
                    for d in dst_ips:
                        key = (s, d)
                        g = result[direction].setdefault(key, {})
                        for proto, ports in proto_ports.items():
                            g.setdefault(proto, set()).update(ports)
        return result

    @staticmethod
    def _expand_endpoint(key: str, wl_by_id: Mapping[str, Workload]) -> List[str]:
        if key.startswith("<") and key.endswith(">"):
            return [key[1:-1]]
        wl = wl_by_id.get(key)
        if not wl:
            return []
        return wl.normalized_ips()

    # ---------- Генераторы бэкендов ----------

    def _compile_nftables(
        self,
        graph: Dict[str, Dict[Tuple[str, str], Dict[str, Set[int]]]],
        workloads: Sequence[Workload],
        policy: Policy,
        traces: List[CompileTrace],
    ) -> Plan:
        """
        Генерация команд nft. Структура:
          table inet zt_<tenant>
            set s_ing_<dst> (allowed sources)
            set s_egr_<src> (allowed destinations)
            chain zt_ing_<dst> { ... }
            chain zt_egr_<src> { ... }
        """
        tname = f"zt_{self.tenant}"
        cmds: List[str] = [
            f"nft add table inet {shlex.quote(tname)} || true",
        ]

        # Создаём базовые цепочки (хуки на discretion — зависит от интеграции на ноде)
        cmds += [
            f"nft 'add chain inet {tname} zt_ingress {{ type filter hook input priority -100; policy drop; }}' || true",
            f"nft 'add chain inet {tname} zt_egress  {{ type filter hook output priority -100; policy drop; }}' || true",
        ]

        # Пустые цепочки-чистильщики
        cmds += [
            f"nft flush chain inet {tname} zt_ingress",
            f"nft flush chain inet {tname} zt_egress",
        ]

        # Правила по графу
        for direction, edges in graph.items():
            for (src, dst), proto_ports in sorted(edges.items()):
                # Определяем набор адресов и правило
                if direction == Direction.INGRESS.value:
                    saddr = self._to_set_name("ing", dst)
                    cmds += self._nft_ensure_set(tname, saddr)
                    cmds += self._nft_add_to_set(tname, saddr, src)
                    chain = "zt_ingress"
                    addr_expr = f"saddr @ {saddr}"
                    target_default = policy.default_action_ingress
                else:
                    daddr = self._to_set_name("egr", src)
                    cmds += self._nft_ensure_set(tname, daddr)
                    cmds += self._nft_add_to_set(tname, daddr, dst)
                    chain = "zt_egress"
                    addr_expr = f"daddr @ {daddr}"
                    target_default = policy.default_action_egress

                for proto, ports in sorted(proto_ports.items()):
                    if -1 in ports:
                        port_expr = ""
                    else:
                        port_list = ",".join(str(p) for p in sorted(ports))
                        if proto in ("tcp", "udp", "sctp"):
                            port_expr = f" {proto} dport {{{port_list}}}"
                        else:
                            port_expr = ""
                    verdict = "accept"  # ALLOW‑правила формируют только разрешения
                    cmds.append(f"nft add rule inet {tname} {chain} {proto} {addr_expr}{port_expr} {verdict}")

        # Политики по умолчанию
        if policy.default_action_ingress == Action.ALLOW:
            cmds.append(f"nft add rule inet {tname} zt_ingress counter accept")
        else:
            cmds.append(f"nft add rule inet {tname} zt_ingress counter drop")

        if policy.default_action_egress == Action.ALLOW:
            cmds.append(f"nft add rule inet {tname} zt_egress counter accept")
        else:
            cmds.append(f"nft add rule inet {tname} zt_egress counter drop")

        return Plan(backend="nftables", items=cmds, traces=traces)

    def _nft_ensure_set(self, tname: str, sname: str) -> List[str]:
        # inet family, тип «addr» (ipv4/ipv6 mixed) через «ct direction expr» невозможен, используем «ip saddr/ipv6 saddr»
        # Для упрощения создаём два набора (ip и ip6) под одним логическим именем не будем — используем generic «set type addr»
        return [
            f"nft 'add set inet {tname} {sname} {{ type addr; flags interval; }}' || true",
            f"nft flush set inet {tname} {sname}",
        ]

    def _nft_add_to_set(self, tname: str, sname: str, endpoint: str) -> List[str]:
        els = []
        # endpoint может быть IP, CIDR
        els.append(endpoint)
        el_csv = ", ".join(shlex.quote(e) for e in els)
        return [f"nft add element inet {tname} {sname} {{ {el_csv} }}"]

    @staticmethod
    def _to_set_name(prefix: str, token: str) -> str:
        # token — это dst (для ingress) или src (для egress): IP/CIDR
        safe = re.sub(r"[^a-zA-Z0-9]", "_", token)[:48]
        return f"s_{prefix}_{safe}"

    def _compile_iptables(
        self,
        graph: Dict[str, Dict[Tuple[str, str], Dict[str, Set[int]]]],
        workloads: Sequence[Workload],
        policy: Policy,
        traces: List[CompileTrace],
    ) -> Plan:
        """
        Упрощённый fallback на iptables (IPv4). Для продакшена предпочтителен nftables.
        """
        chain_in = f"ZT_IN_{self.tenant}".upper()
        chain_out = f"ZT_OUT_{self.tenant}".upper()
        cmds = [
            f"iptables -N {chain_in} 2>/dev/null || true",
            f"iptables -F {chain_in}",
            f"iptables -N {chain_out} 2>/dev/null || true",
            f"iptables -F {chain_out}",
            # Подключение к INPUT/OUTPUT выполняется вне плана (в руках оркестратора),
            # например: iptables -I INPUT -j {chain_in}; iptables -I OUTPUT -j {chain_out}
        ]
        for direction, edges in graph.items():
            for (src, dst), proto_ports in sorted(edges.items()):
                for proto, ports in sorted(proto_ports.items()):
                    base = "iptables -A {chain} -p {proto} {addr} -j ACCEPT"
                    if direction == Direction.INGRESS.value:
                        addr = f"-s {shlex.quote(src)} -d {shlex.quote(dst)}"
                        chain = chain_in
                    else:
                        addr = f"-s {shlex.quote(src)} -d {shlex.quote(dst)}"
                        chain = chain_out
                    if -1 in ports:
                        cmds.append(base.format(chain=chain, proto=self._ipt_proto(proto), addr=addr))
                    else:
                        for p in sorted(ports):
                            port_flag = "--dport" if proto in ("tcp", "udp", "sctp") else ""
                            cmds.append(
                                f"iptables -A {chain} -p {self._ipt_proto(proto)} {addr} {port_flag} {p} -j ACCEPT".strip()
                            )
        # Политики по умолчанию (здесь — явные REJECT/DROP в конце цепочки)
        if policy.default_action_ingress == Action.DENY:
            cmds.append(f"iptables -A {chain_in} -j DROP")
        if policy.default_action_egress == Action.DENY:
            cmds.append(f"iptables -A {chain_out} -j DROP")

        return Plan(backend="iptables", items=cmds, traces=traces)

    @staticmethod
    def _ipt_proto(proto: str) -> str:
        return "icmp" if proto == "icmp" else proto

    def _compile_k8s(
        self,
        graph: Dict[str, Dict[Tuple[str, str], Dict[str, Set[int]]]],
        workloads: Sequence[Workload],
        policy: Policy,
        namespace: str,
        traces: List[CompileTrace],
    ) -> Plan:
        """
        Генерация Kubernetes NetworkPolicy (стандартный API).
        Для identity‑aware реализаций (Cilium/Calico eBPF) можно расширять через аннотации.
        """
        # Группируем по dst (ingress) и src (egress)
        by_dst_ing: Dict[str, List[Tuple[str, str, str, Set[int]]]] = {}
        by_src_egr: Dict[str, List[Tuple[str, str, str, Set[int]]]] = {}

        for (src, dst), proto_ports in graph[Direction.INGRESS.value].items():
            for proto, ports in proto_ports.items():
                by_dst_ing.setdefault(dst, []).append((src, dst, proto, ports))
        for (src, dst), proto_ports in graph[Direction.EGRESS.value].items():
            for proto, ports in proto_ports.items():
                by_src_egr.setdefault(src, []).append((src, dst, proto, ports))

        # Индекс меток по IP для сопоставления podSelector
        labels_by_ip: Dict[str, Mapping[str, str]] = {}
        for w in workloads:
            for ip in w.normalized_ips():
                # ip может быть сетью — для k8s используем только Pod IP (одиночный)
                if "/" not in ip:
                    labels_by_ip[ip] = w.labels

        yamls: List[str] = []

        # Ingress policies per destination
        for dst, lst in sorted(by_dst_ing.items()):
            spec = self._k8s_np(
                name=f"zt-ing-{self._safe_name(dst)}",
                namespace=namespace,
                pod_selector=labels_by_ip.get(dst, {}),
                direction="ingress",
                peers=[self._k8s_peer(src, labels_by_ip) for (src, _, _, __) in lst],
                rules=[self._k8s_rule(proto, ports) for (_, __, proto, ports) in lst],
                default=policy.default_action_ingress,
            )
            yamls.append(spec)

        # Egress policies per source
        for src, lst in sorted(by_src_egr.items()):
            spec = self._k8s_np(
                name=f"zt-egr-{self._safe_name(src)}",
                namespace=namespace,
                pod_selector=labels_by_ip.get(src, {}),
                direction="egress",
                peers=[self._k8s_peer(dst, labels_by_ip) for (_, dst, _, __) in lst],
                rules=[self._k8s_rule(proto, ports) for (__, ___, proto, ports) in lst],
                default=policy.default_action_egress,
            )
            yamls.append(spec)

        return Plan(backend="k8s", items=yamls, traces=traces)

    # ---------- Утилиты Kubernetes ----------

    @staticmethod
    def _safe_name(s: str) -> str:
        return re.sub(r"[^a-z0-9-]", "-", s.lower())[:63].strip("-") or "any"

    @staticmethod
    def _k8s_rule(proto: str, ports: Set[int]) -> Mapping[str, object]:
        if -1 in ports:
            plist: List[Mapping[str, object]] = []
        else:
            plist = [{"protocol": proto.upper(), "port": p} for p in sorted(ports)]
        return {"ports": plist}

    @staticmethod
    def _k8s_peer(endpoint: str, labels_by_ip: Mapping[str, Mapping[str, str]]) -> Mapping[str, object]:
        if endpoint in labels_by_ip:
            # podSelector по меткам назначения/источника
            m = labels_by_ip[endpoint]
            return {"podSelector": {"matchLabels": m}}
        else:
            # ipBlock
            cidr = endpoint if "/" in endpoint else f"{endpoint}/32"
            return {"ipBlock": {"cidr": cidr}}

    def _k8s_np(
        self,
        name: str,
        namespace: str,
        pod_selector: Mapping[str, str],
        direction: str,
        peers: List[Mapping[str, object]],
        rules: List[Mapping[str, object]],
        default: Action,
    ) -> str:
        # Стандартная NetworkPolicy — deny‑all по умолчанию достигается отдельной политикой или отсутствием разрешений.
        # Здесь генерируем policy с явными from/to и разрешёнными портами.
        spec_dir = "ingress" if direction == "ingress" else "egress"
        item = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace, "labels": {"zt.aethernova/tenant": self.tenant}},
            "spec": {
                "podSelector": {"matchLabels": pod_selector} if pod_selector else {},
                "policyTypes": [spec_dir],
                spec_dir: [{"from" if spec_dir == "ingress" else "to": peers, **r} for r in rules] or ([] if default == Action.ALLOW else [{}]),
            },
        }
        # Красивое форматирование YAML (без внешних зависимостей) — простая конверсия через JSON + «псевдо‑yaml».
        return _json_to_yaml(item)


# -----------------------------
# Простейший JSON->YAML (без PyYAML)
# -----------------------------

def _json_to_yaml(obj: object, indent: int = 0) -> str:
    def _emit(o: object, level: int) -> str:
        pad = "  " * level
        if isinstance(o, dict):
            lines: List[str] = []
            for k, v in o.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{pad}{k}:")
                    lines.append(_emit(v, level + 1))
                else:
                    lines.append(f"{pad}{k}: {_scalar(v)}")
            return "\n".join(lines)
        if isinstance(o, list):
            lines = []
            for it in o:
                if isinstance(it, (dict, list)):
                    lines.append(f"{pad}-")
                    lines.append(_emit(it, level + 1))
                else:
                    lines.append(f"{pad}- {_scalar(it)}")
            return "\n".join(lines)
        return f"{pad}{_scalar(o)}"

    def _scalar(v: object) -> str:
        if v is True:
            return "true"
        if v is False:
            return "false"
        if v is None:
            return "null"
        if isinstance(v, (int, float)):
            return str(v)
        s = str(v)
        if re.search(r"[:{}\[\],#&*!|>'\"%@`]|^\s|\s$", s):
            return json.dumps(s)
        return s

    return _emit(obj, indent) + "\n"


# -----------------------------
# Пример использования (doctest)
# -----------------------------

if __name__ == "__main__":
    # Пример: два ворклоада и одна политика allow от web -> api по TCP/443
    web = Workload(wid="web", labels={"tier": "web", "env": "prod"}, ip_addrs=["10.0.1.10"])
    api = Workload(wid="api", labels={"tier": "api", "env": "prod"}, ip_addrs=["10.0.2.20"])

    rule = Rule(
        action=Action.ALLOW,
        direction=Direction.EGRESS,
        src=Selector.from_query("tier=web,env=prod"),
        dst=Selector.from_query("tier=api,env=prod"),
        protocols={Protocol.TCP},
        ports=[PortRange.single(443)],
        description="web->api https",
        priority=10,
    )
    pol = Policy(rules=[rule], name="prod", default_action_ingress=Action.DENY, default_action_egress=Action.DENY)

    compiler = MicrosegmentationCompiler(tenant="acme")
    plan = compiler.compile([web, api], pol, backend="nftables")
    print(plan.dry_run())
