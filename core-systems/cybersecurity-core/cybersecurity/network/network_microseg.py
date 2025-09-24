# cybersecurity-core/cybersecurity/network/network_microseg.py
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, time as dtime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

try:
    import psutil  # optional, для инвентаризации потоков
except Exception:
    psutil = None  # type: ignore

from pydantic import BaseModel, Field, ValidationError, conint, constr, validator

__all__ = [
    "Endpoint",
    "EndpointSelector",
    "Service",
    "Rule",
    "Policy",
    "CompileOptions",
    "CompileResult",
    "FirewallProvider",
    "NftablesProvider",
    "WindowsFirewallProvider",
    "PfProvider",
    "MicrosegEngine",
    "SimulationRequest",
    "SimulationResult",
    "FlowRecord",
    "discover_active_flows",
]

# ------------------------------------------------------------------------------
# Логирование
# ------------------------------------------------------------------------------
logger = logging.getLogger("network.microseg")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Модели домена
# ------------------------------------------------------------------------------

class Endpoint(BaseModel):
    """
    Локальная сущность для микросегментации: хост/интерфейс/зона.
    Для хоста: ip_cidrs = адреса/подсети, labels = произвольные теги (zone=frontend).
    """
    name: constr(strip_whitespace=True, min_length=1, max_length=128)
    ip_cidrs: List[constr(strip_whitespace=True, min_length=1)] = Field(default_factory=list)
    interfaces: List[constr(strip_whitespace=True, min_length=1)] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    tenant: Optional[str] = None
    os_family: Optional[Literal["linux", "windows", "darwin"]] = None

    @validator("ip_cidrs", each_item=True)
    def _v_cidr(cls, v: str) -> str:
        ipaddress.ip_network(v, strict=False)
        return v


class EndpointSelector(BaseModel):
    """
    Селектор по меткам/подсетям/именам: задает множество источников/назначений для правила.
    Любое из условий может быть использовано, пустой селектор = "любой".
    """
    names: List[str] = Field(default_factory=list)
    label_eq: Dict[str, str] = Field(default_factory=dict)
    ip_cidrs: List[str] = Field(default_factory=list)

    @validator("ip_cidrs", each_item=True)
    def _v_cidr(cls, v: str) -> str:
        ipaddress.ip_network(v, strict=False)
        return v


class Service(BaseModel):
    """
    L4-сервис: протокол и порт(ы).
    """
    protocol: Literal["tcp", "udp", "icmp", "any"] = "tcp"
    ports: List[conint(ge=0, le=65535)] = Field(default_factory=list)
    port_range: Optional[Tuple[conint(ge=0, le=65535), conint(ge=0, le=65535)]] = None

    @validator("port_range")
    def _v_range(cls, v):
        if v and v[0] > v[1]:
            raise ValueError("port_range: start > end")
        return v


class TimeWindow(BaseModel):
    """
    Окно времени для правила (UTC): "HH:MM-HH:MM".
    """
    window: constr(strip_whitespace=True, regex=r"^\d{2}:\d{2}-\d{2}:\d{2}$")

    def contains(self, dt: datetime) -> bool:
        a, b = self.window.split("-")
        t1 = dtime(int(a[:2]), int(a[3:]), tzinfo=timezone.utc)
        t2 = dtime(int(b[:2]), int(b[3:]), tzinfo=timezone.utc)
        tv = dt.timetz()
        if t1 <= t2:
            return t1 <= tv <= t2
        return tv >= t1 or tv <= t2


class Rule(BaseModel):
    """
    Правило микросегментации: кто->куда, какой сервис, действие, направление, приоритет.
    """
    rule_id: constr(strip_whitespace=True, min_length=1) = Field(default_factory=lambda: f"r-{uuid.uuid4()}")
    name: constr(strip_whitespace=True, min_length=1, max_length=200)
    src: EndpointSelector = Field(default_factory=EndpointSelector)
    dst: EndpointSelector = Field(default_factory=EndpointSelector)
    service: Service = Field(default_factory=Service)
    direction: Literal["ingress", "egress", "both"] = "both"
    action: Literal["allow", "deny"] = "allow"
    priority: conint(ge=0, le=1_000_000) = 1000
    log: bool = True
    enabled: bool = True
    time_window: Optional[TimeWindow] = None
    description: Optional[str] = None


class Policy(BaseModel):
    """
    Политика: набор правил + базлайн (loopback/established).
    """
    policy_id: constr(strip_whitespace=True, min_length=1) = Field(default_factory=lambda: f"p-{uuid.uuid4()}")
    tenant: Optional[str] = None
    endpoints: List[Endpoint] = Field(default_factory=list)
    rules: List[Rule] = Field(default_factory=list)
    baseline_allow_loopback: bool = True
    baseline_allow_established: bool = True
    default_drop_ingress: bool = True
    default_drop_egress: bool = False


# ------------------------------------------------------------------------------
# Инвентаризация активных потоков (learning mode)
# ------------------------------------------------------------------------------
@dataclass
class FlowRecord:
    laddr: str
    lport: int
    raddr: str
    rport: int
    proto: str
    state: str
    pid: Optional[int] = None
    process: Optional[str] = None


def _flows_psutil() -> List[FlowRecord]:
    if not psutil:
        return []
    res: List[FlowRecord] = []
    proto_map = {socket.SOCK_STREAM: "tcp", socket.SOCK_DGRAM: "udp"}
    for conn in psutil.net_connections(kind="inet"):  # type: ignore
        proto = proto_map.get(conn.type, "tcp")
        laddr = conn.laddr.ip if conn.laddr else ""
        lport = conn.laddr.port if conn.laddr else 0
        raddr = conn.raddr.ip if conn.raddr else ""
        rport = conn.raddr.port if conn.raddr else 0
        pname = None
        try:
            if conn.pid:
                pname = psutil.Process(conn.pid).name()
        except Exception:
            pname = None
        res.append(FlowRecord(laddr, lport, raddr, rport, proto, str(conn.status), conn.pid, pname))
    return res


def _flows_netstat() -> List[FlowRecord]:
    # Фоллбэк через системный netstat/ss
    cmds = [
        ("linux", ["ss", "-tunap"]),
        ("darwin", ["netstat", "-anv"]),
        ("windows", ["netstat", "-ano"]),
    ]
    system = platform.system().lower()
    cmd = None
    for osname, c in cmds:
        if osname in system:
            cmd = c
            break
    if not cmd:
        return []
    try:
        out = subprocess.check_output(cmd, text=True, errors="ignore", timeout=5)
    except Exception:
        return []
    res: List[FlowRecord] = []
    for line in out.splitlines():
        if "tcp" in line or "udp" in line:
            # очень грубый парсер; для prod рекомендуется использовать psutil
            proto = "tcp" if "tcp" in line else "udp"
            parts = re.split(r"\s+", line.strip())
            # на разных ОС форматы различаются; извлечем адреса через regex host:port
            m = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
            if len(m) >= 2:
                (laddr, lport), (raddr, rport) = m[0], m[1]
                res.append(FlowRecord(laddr, int(lport), raddr, int(rport), proto, state=parts[-1] if parts else ""))
    return res


def discover_active_flows() -> List[FlowRecord]:
    flows = _flows_psutil()
    if not flows:
        flows = _flows_netstat()
    return flows


# ------------------------------------------------------------------------------
# Компилятор и план применения
# ------------------------------------------------------------------------------

@dataclass
class CompileOptions:
    dry_run: bool = True
    allow_exec: bool = False
    table_name: str = "microseg"
    anchor_name: str = "microseg"
    comment_prefix: str = "MICROSEG"
    ensure_baseline: bool = True


@dataclass
class Command:
    cmd: List[str]
    shell: bool = False


@dataclass
class CompileResult:
    commands: List[Command]
    provider: str
    plan_hash: str
    issues: List[str] = field(default_factory=list)


# ------------------------------------------------------------------------------
# Провайдеры (Firewall backends)
# ------------------------------------------------------------------------------

class FirewallProvider:
    """
    Базовый интерфейс. Реализации должны генерировать команды и (опционально) уметь читать текущее состояние.
    """
    def __init__(self, opts: CompileOptions) -> None:
        self.opts = opts

    def compile(self, policy: Policy) -> CompileResult:  # pragma: no cover
        raise NotImplementedError


class NftablesProvider(FirewallProvider):
    """
    Linux nftables (таблица inet). Генерирует атомарный 'nft -f' план.
    """
    def compile(self, policy: Policy) -> CompileResult:
        table = self.opts.table_name
        comment_tag = f"{self.opts.comment_prefix}:{policy.policy_id}"

        # Базовые цепочки
        lines = [
            f"table inet {table} {{",
            "  sets { }",
            "  chains { }",
            "}",
            "",
            f"flush table inet {table}",
            f"table inet {table} {{",
            "  chain ingress {",
            "    type filter hook input priority 0;",
            "    ct state established,related accept",
            "  }",
            "  chain egress {",
            "    type filter hook output priority 0;",
            "    ct state established,related accept",
            "  }",
            "}",
        ]

        # Базлайн
        if policy.baseline_allow_loopback:
            lines.insert(-1, f"  chain loopback {{ type filter hook input priority -300; iif lo accept; }}")
            lines.append(f"add rule inet {table} egress oif lo accept comment \"{comment_tag}:baseline\"")

        # Сформируем список правил с сортировкой по приоритету (DENY-overrides выше по умолчанию)
        active_rules = [r for r in policy.rules if r.enabled]
        active_rules.sort(key=lambda r: (r.priority, 0 if r.action == "deny" else 1, r.name))

        def _ports_expr(svc: Service) -> str:
            if svc.protocol == "icmp":
                return "icmp type echo-request"
            if svc.port_range:
                a, b = svc.port_range
                return f"dport {a}-{b}"
            if svc.ports:
                if len(svc.ports) == 1:
                    return f"dport {svc.ports[0]}"
                ports = ",".join(str(p) for p in sorted(set(svc.ports)))
                return f"dport {{{ports}}}"
            return ""  # any

        def _cidr_expr(sel: EndpointSelector, src: bool) -> List[str]:
            exprs: List[str] = []
            if sel.ip_cidrs:
                joined = ",".join(sel.ip_cidrs)
                exprs.append(f"{'saddr' if src else 'daddr'} {{ {joined} }}")
            # метки и имена на уровне nft не поддерживаются — селекторы должны быть резолвнуты заранее
            return exprs

        # Раскрытие EndpointSelector до IP-сетей
        def _resolve_ips(sel: EndpointSelector, endpoints: List[Endpoint]) -> List[str]:
            nets: List[str] = []
            s_names = set(sel.names or [])
            label_items = list(sel.label_eq.items()) if sel.label_eq else []
            for ep in endpoints:
                if s_names and ep.name not in s_names:
                    continue
                ok = True
                for k, v in label_items:
                    if ep.labels.get(k) != v:
                        ok = False
                        break
                if not ok:
                    continue
                nets.extend(ep.ip_cidrs)
            nets.extend(sel.ip_cidrs or [])
            # валидация уже была в моделях
            return sorted(set(nets))

        # Правила ingress/egress
        for r in active_rules:
            # окно времени
            if r.time_window and not r.time_window.contains(datetime.now(timezone.utc)):
                # всё равно генерируем, но с меткой; операционная проверка времени может быть вне nft
                pass

            src_nets = _resolve_ips(r.src, policy.endpoints)
            dst_nets = _resolve_ips(r.dst, policy.endpoints)

            def _emit(direction: str, s_nets: List[str], d_nets: List[str]) -> None:
                base = f"add rule inet {table} {{chain}} "
                proto = "" if r.service.protocol == "any" else f"{r.service.protocol} "
                port_expr = _ports_expr(r.service)
                # Разобьем по всем комбинациям сетей, чтобы остаться читаемыми
                s_expr = f"saddr {{ {', '.join(s_nets)} }} " if s_nets else ""
                d_expr = f"daddr {{ {', '.join(d_nets)} }} " if d_nets else ""
                action = "accept" if r.action == "allow" else "drop"
                log = "log prefix \"MICROSEG\" " if r.log else ""
                cm = f"comment \"{comment_tag}:{r.rule_id}:{r.name}\""
                expr = f"{proto}{s_expr}{d_expr}{port_expr} {log}{action} {cm}".strip()
                chain = "ingress" if direction == "ingress" else "egress"
                lines.append(base.replace("{chain}", chain) + expr)

            if r.direction in ("ingress", "both"):
                _emit("ingress", src_nets, dst_nets)
            if r.direction in ("egress", "both"):
                _emit("egress", src_nets, dst_nets)

        # Политики по умолчанию
        if policy.default_drop_ingress:
            lines.append(f"add rule inet {table} ingress counter drop comment \"{comment_tag}:default_drop_ingress\"")
        else:
            lines.append(f"add rule inet {table} ingress counter accept comment \"{comment_tag}:default_allow_ingress\"")

        if policy.default_drop_egress:
            lines.append(f"add rule inet {table} egress counter drop comment \"{comment_tag}:default_drop_egress\"")
        else:
            lines.append(f"add rule inet {table} egress counter accept comment \"{comment_tag}:default_allow_egress\"")

        # Завершаем блок
        lines.append("}")

        plan_txt = "\n".join(lines)
        plan_hash = hashlib.sha256(plan_txt.encode("utf-8")).hexdigest()[:16]
        cmd = Command(cmd=["nft", "-f", "-"], shell=False)

        # Если исполняем, подадим план на stdin, иначе сохраним во временный файл
        commands: List[Command] = [cmd]
        issues: List[str] = []
        return CompileResult(commands=commands, provider="nftables", plan_hash=plan_hash, issues=issues)


class WindowsFirewallProvider(FirewallProvider):
    """
    Windows Advanced Firewall (netsh advfirewall). Генерирует idempotent-правила с группой "Microseg".
    """
    def compile(self, policy: Policy) -> CompileResult:
        group = "Microseg"
        comment_tag = f"{self.opts.comment_prefix}:{policy.policy_id}"
        cmds: List[Command] = []
        issues: List[str] = []

        # Сброс группы
        cmds.append(Command(cmd=["cmd", "/c", f'netsh advfirewall firewall delete rule group="{group}"']))

        active = [r for r in policy.rules if r.enabled]
        active.sort(key=lambda r: (r.priority, 0 if r.action == "deny" else 1, r.name))

        def _addr_list(sel: EndpointSelector, endp: List[Endpoint], src: bool) -> str:
            nets = set(sel.ip_cidrs or [])
            names = set(sel.names or [])
            for ep in endp:
                if names and ep.name not in names:
                    continue
                ok = all(ep.labels.get(k) == v for k, v in (sel.label_eq or {}).items())
                if ok:
                    nets.update(ep.ip_cidrs)
            if not nets:
                return "any"
            return ",".join(sorted(nets))

        for r in active:
            proto = "ANY" if r.service.protocol == "any" else r.service.protocol.upper()
            ports = ""
            if r.service.port_range:
                a, b = r.service.port_range
                ports = f"localport={a}-{b}"
            elif r.service.ports:
                ports = f"localport={','.join(str(p) for p in sorted(set(r.service.ports)))}"
            else:
                ports = "localport=any"

            direction = "in" if r.direction in ("ingress", "both") else "out"
            action = "allow" if r.action == "allow" else "block"

            src = _addr_list(r.src, policy.endpoints, True)
            dst = _addr_list(r.dst, policy.endpoints, False)

            # Windows FW в терминах local/remote; для inbound local — это dst, remote — src
            if direction == "in":
                local = dst
                remote = src
            else:
                local = src
                remote = dst

            name = f"{comment_tag}:{r.rule_id}:{r.name}"[:245]
            base = [
                "cmd", "/c", "netsh", "advfirewall", "firewall", "add", "rule",
                f'name="{name}"',
                f'group="{group}"',
                f"dir={direction}",
                f"action={action}",
                f"protocol={proto}",
                ports,
                f"remoteip={remote}",
                # localip можно не задавать (any)
                "enable=yes",
            ]
            cmds.append(Command(cmd=base))
        plan_txt = json.dumps([c.cmd for c in cmds], ensure_ascii=False)
        plan_hash = hashlib.sha256(plan_txt.encode("utf-8")).hexdigest()[:16]
        return CompileResult(commands=cmds, provider="windows_firewall", plan_hash=plan_hash, issues=issues)


class PfProvider(FirewallProvider):
    """
    macOS/BSD pf через anchors. Генерирует файл-анкёр и команду загрузки.
    """
    def compile(self, policy: Policy) -> CompileResult:
        anchor = self.opts.anchor_name
        comment_tag = f"{self.opts.comment_prefix}:{policy.policy_id}"
        rules: List[str] = [f"# {comment_tag}", f"anchor \"{anchor}\" {{}}"]
        body: List[str] = []

        def _addr(sel: EndpointSelector) -> str:
            nets = sel.ip_cidrs or []
            if not nets:
                return "any"
            return "{" + ", ".join(nets) + "}"

        def _ports(svc: Service) -> str:
            if svc.port_range:
                a, b = svc.port_range
                return f"port {a}:{b}"
            if svc.ports:
                if len(svc.ports) == 1:
                    return f"port {svc.ports[0]}"
                return "port {" + ", ".join(str(p) for p in sorted(set(svc.ports))) + "}"
            return ""

        active = [r for r in policy.rules if r.enabled]
        active.sort(key=lambda r: (r.priority, 0 if r.action == "deny" else 1, r.name))
        for r in active:
            act = "pass" if r.action == "allow" else "block"
            proto = "proto " + (r.service.protocol if r.service.protocol != "any" else "tcp")
            src = _addr(r.src)
            dst = _addr(r.dst)
            prts = _ports(r.service)
            log = "log" if r.log else ""
            direction = ""  # pf не требует отдельной цепочки
            body.append(f"{act} {log} {proto} from {src} to {dst} {prts} # {comment_tag}:{r.rule_id}:{r.name}")

        # Базовые
        if policy.baseline_allow_loopback:
            body.insert(0, "set skip on lo0")
        if policy.baseline_allow_established:
            body.insert(0, "pass quick proto { tcp, udp } from any to any flags S/SA keep state")

        if policy.default_drop_ingress:
            body.append("block in all")
        if policy.default_drop_egress:
            body.append("block out all")

        anchor_file = f"/etc/pf.anchors/{anchor}"
        cmds = [
            Command(cmd=["sh", "-lc", f"printf %s {shlex.quote('\\n'.join(body))} | sudo tee {shlex.quote(anchor_file)} >/dev/null"]),
            Command(cmd=["sh", "-lc", f"sudo pfctl -f {shlex.quote(anchor_file)} && sudo pfctl -E && sudo pfctl -sr | grep {shlex.quote(anchor)}"]),
        ]
        plan_txt = "\n".join(body)
        plan_hash = hashlib.sha256(plan_txt.encode("utf-8")).hexdigest()[:16]
        return CompileResult(commands=cmds, provider="pf", plan_hash=plan_hash, issues=[])


# ------------------------------------------------------------------------------
# Симуляция/валидация
# ------------------------------------------------------------------------------

class SimulationRequest(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: Literal["tcp", "udp", "icmp"]
    port: Optional[int] = None
    direction: Literal["ingress", "egress"] = "ingress"


class SimulationResult(BaseModel):
    allowed: bool
    matched_rule_id: Optional[str]
    reason: str


def _ip_in(ip: str, cidrs: Iterable[str]) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in ipaddress.ip_network(n, strict=False) for n in cidrs)


def simulate(policy: Policy, req: SimulationRequest) -> SimulationResult:
    """
    Быстрый симулятор на базе декларативных правил (L3/L4).
    """
    # Базлайн established/loopback не учитываем явно в симуляции (только L3/L4 по правилам).
    active = [r for r in policy.rules if r.enabled]
    active.sort(key=lambda r: (r.priority, 0 if r.action == "deny" else 1, r.name))
    now = datetime.now(timezone.utc)

    for r in active:
        if r.time_window and not r.time_window.contains(now):
            continue
        if r.direction not in (req.direction, "both"):
            continue
        if r.service.protocol not in (req.protocol, "any", ("tcp" if req.protocol in ("tcp", "udp") and r.service.protocol == "any" else "")):
            # грубая проверка
            pass
        # Сопоставление адресов
        src_nets = list(r.src.ip_cidrs)
        dst_nets = list(r.dst.ip_cidrs)
        for ep in policy.endpoints:
            ok_src = all(ep.labels.get(k) == v for k, v in (r.src.label_eq or {}).items())
            ok_dst = all(ep.labels.get(k) == v for k, v in (r.dst.label_eq or {}).items())
            if ok_src and (not r.src.names or ep.name in r.src.names):
                src_nets.extend(ep.ip_cidrs)
            if ok_dst and (not r.dst.names or ep.name in r.dst.names):
                dst_nets.extend(ep.ip_cidrs)
        if src_nets and not _ip_in(req.src_ip, src_nets):
            continue
        if dst_nets and not _ip_in(req.dst_ip, dst_nets):
            continue
        # Порты
        if req.port is not None:
            if r.service.port_range:
                a, b = r.service.port_range
                if not (a <= req.port <= b):
                    continue
            elif r.service.ports:
                if req.port not in r.service.ports:
                    continue
        allowed = r.action == "allow"
        return SimulationResult(allowed=allowed, matched_rule_id=r.rule_id, reason=f"matched:{r.name}")
    # По умолчанию — default policy
    if req.direction == "ingress":
        allowed = not policy.default_drop_ingress
    else:
        allowed = not policy.default_drop_egress
    return SimulationResult(allowed=allowed, matched_rule_id=None, reason="default")


# ------------------------------------------------------------------------------
# Движок микросегментации
# ------------------------------------------------------------------------------

class MicrosegEngine:
    def __init__(self, opts: Optional[CompileOptions] = None) -> None:
        self.opts = opts or CompileOptions()

    def _detect_provider(self) -> FirewallProvider:
        s = platform.system().lower()
        if "linux" in s:
            return NftablesProvider(self.opts)
        if "windows" in s:
            return WindowsFirewallProvider(self.opts)
        if "darwin" in s:
            return PfProvider(self.opts)
        # По умолчанию — nftables
        return NftablesProvider(self.opts)

    def validate(self, policy: Policy) -> List[str]:
        """
        Статическая валидация: перекрытия и противоречия (allow vs deny с большим/меньшим приоритетом).
        """
        issues: List[str] = []
        active = [r for r in policy.rules if r.enabled]
        # Одинаковые направления/пересекающиеся селекторы и сервисы
        for i in range(len(active)):
            for j in range(i + 1, len(active)):
                a, b = active[i], active[j]
                if a.direction != b.direction and "both" not in (a.direction, b.direction):
                    continue
                if a.action == b.action:
                    continue
                # Приоритет: меньший = раньше
                if a.priority == b.priority:
                    issues.append(f"priority.conflict: rules {a.name} and {b.name} have same priority with opposite actions")
        # Валидация окон времени
        for r in active:
            if r.time_window:
                try:
                    _ = r.time_window.contains(datetime.now(timezone.utc))
                except Exception as ex:
                    issues.append(f"time_window.invalid:{r.name}:{ex}")
        return issues

    def compile(self, policy: Policy, provider: Optional[FirewallProvider] = None) -> CompileResult:
        provider = provider or self._detect_provider()
        issues = self.validate(policy)
        res = provider.compile(policy)
        res.issues.extend(issues)
        return res

    def apply(self, policy: Policy, allow_exec: Optional[bool] = None, provider: Optional[FirewallProvider] = None) -> CompileResult:
        """
        Применение плана. По умолчанию безопасный режим: только возвращает план команд.
        Для реального выполнения установите allow_exec=True.
        """
        provider = provider or self._detect_provider()
        res = self.compile(policy, provider)
        do_exec = self.opts.allow_exec if allow_exec is None else allow_exec
        if not do_exec:
            logger.info("Dry-run: provider=%s plan_hash=%s commands=%d", res.provider, res.plan_hash, len(res.commands))
            return res

        # Исполнение команд с пайпом для nft -f
        if res.provider == "nftables":
            plan_lines = self._render_nft_plan(policy)
            proc = subprocess.Popen(["nft", "-f", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = proc.communicate(plan_lines, timeout=10)
            if proc.returncode != 0:
                raise RuntimeError(f"nft apply failed: {err}")
            logger.info("nft applied: %s", res.plan_hash)
        else:
            for c in res.commands:
                logger.debug("exec: %s", " ".join(c.cmd))
                subprocess.check_call(c.cmd, timeout=15)
        return res

    # Вспомогательный рендер для nft (синхронен compile)
    def _render_nft_plan(self, policy: Policy) -> str:
        provider = NftablesProvider(self.opts)
        # Используем приватный путь генерации через compile() и интерпретацию текста команд
        # Здесь повторим логику генерации
        table = self.opts.table_name
        comment_tag = f"{self.opts.comment_prefix}:{policy.policy_id}"

        lines = [
            f"table inet {table} {{",
            "  sets { }",
            "  chains { }",
            "}",
            "",
            f"flush table inet {table}",
            f"table inet {table} {{",
            "  chain ingress {",
            "    type filter hook input priority 0;",
            "    ct state established,related accept",
            "  }",
            "  chain egress {",
            "    type filter hook output priority 0;",
            "    ct state established,related accept",
            "  }",
            "}",
        ]
        if policy.baseline_allow_loopback:
            lines.insert(-1, f"  chain loopback {{ type filter hook input priority -300; iif lo accept; }}")
            lines.append(f"add rule inet {table} egress oif lo accept comment \"{comment_tag}:baseline\"")

        active_rules = [r for r in policy.rules if r.enabled]
        active_rules.sort(key=lambda r: (r.priority, 0 if r.action == "deny" else 1, r.name))

        def _ports_expr(svc: Service) -> str:
            if svc.protocol == "icmp":
                return "icmp type echo-request"
            if svc.port_range:
                a, b = svc.port_range
                return f"dport {a}-{b}"
            if svc.ports:
                if len(svc.ports) == 1:
                    return f"dport {svc.ports[0]}"
                ports = ",".join(str(p) for p in sorted(set(svc.ports)))
                return f"dport {{{ports}}}"
            return ""

        def _resolve_ips(sel: EndpointSelector, endpoints: List[Endpoint]) -> List[str]:
            nets: List[str] = []
            s_names = set(sel.names or [])
            label_items = list(sel.label_eq.items()) if sel.label_eq else []
            for ep in endpoints:
                if s_names and ep.name not in s_names:
                    continue
                ok = True
                for k, v in label_items:
                    if ep.labels.get(k) != v:
                        ok = False
                        break
                if not ok:
                    continue
                nets.extend(ep.ip_cidrs)
            nets.extend(sel.ip_cidrs or [])
            return sorted(set(nets))

        for r in active_rules:
            src_nets = _resolve_ips(r.src, policy.endpoints)
            dst_nets = _resolve_ips(r.dst, policy.endpoints)
            base = f"add rule inet {table} {{chain}} "
            proto = "" if r.service.protocol == "any" else f"{r.service.protocol} "
            port_expr = _ports_expr(r.service)
            s_expr = f"saddr {{ {', '.join(src_nets)} }} " if src_nets else ""
            d_expr = f"daddr {{ {', '.join(dst_nets)} }} " if dst_nets else ""
            action = "accept" if r.action == "allow" else "drop"
            log = "log prefix \"MICROSEG\" " if r.log else ""
            cm = f"comment \"{comment_tag}:{r.rule_id}:{r.name}\""
            expr = f"{proto}{s_expr}{d_expr}{port_expr} {log}{action} {cm}".strip()
            if r.direction in ("ingress", "both"):
                lines.append(base.replace("{chain}", "ingress") + expr)
            if r.direction in ("egress", "both"):
                lines.append(base.replace("{chain}", "egress") + expr)

        if policy.default_drop_ingress:
            lines.append(f"add rule inet {table} ingress counter drop comment \"{comment_tag}:default_drop_ingress\"")
        else:
            lines.append(f"add rule inet {table} ingress counter accept comment \"{comment_tag}:default_allow_ingress\"")

        if policy.default_drop_egress:
            lines.append(f"add rule inet {table} egress counter drop comment \"{comment_tag}:default_drop_egress\"")
        else:
            lines.append(f"add rule inet {table} egress counter accept comment \"{comment_tag}:default_allow_egress\"")

        lines.append("}")
        return "\n".join(lines)


# ------------------------------------------------------------------------------
# Пример сборки политики из окружения (infra-friendly)
# ------------------------------------------------------------------------------

def policy_from_env(env: Optional[Dict[str, str]] = None) -> Policy:
    e = env or os.environ
    # endpoints/rules ожидаются в JSON (для GitOps)
    endpoints_json = e.get("MICROSEG_ENDPOINTS_JSON", "[]")
    rules_json = e.get("MICROSEG_RULES_JSON", "[]")
    try:
        endpoints = [Endpoint(**x) for x in json.loads(endpoints_json)]
    except Exception as ex:
        logger.error("Invalid MICROSEG_ENDPOINTS_JSON: %s", ex)
        endpoints = []
    try:
        rules = [Rule(**x) for x in json.loads(rules_json)]
    except Exception as ex:
        logger.error("Invalid MICROSEG_RULES_JSON: %s", ex)
        rules = []
    pol = Policy(
        policy_id=e.get("MICROSEG_POLICY_ID", f"p-{uuid.uuid4()}"),
        tenant=e.get("MICROSEG_TENANT"),
        endpoints=endpoints,
        rules=rules,
        baseline_allow_loopback=e.get("MICROSEG_BASELINE_LOOPBACK", "true").lower() == "true",
        baseline_allow_established=e.get("MICROSEG_BASELINE_ESTABLISHED", "true").lower() == "true",
        default_drop_ingress=e.get("MICROSEG_DEFAULT_DROP_INGRESS", "true").lower() == "true",
        default_drop_egress=e.get("MICROSEG_DEFAULT_DROP_EGRESS", "false").lower() == "true",
    )
    return pol


# ------------------------------------------------------------------------------
# CLI-вход (безопасный dry-run по умолчанию)
# ------------------------------------------------------------------------------

def _main(argv: List[str]) -> int:  # pragma: no cover
    import argparse
    ap = argparse.ArgumentParser(description="Microsegmentation compiler/apply")
    ap.add_argument("--apply", action="store_true", help="apply plan (dangerous)")
    ap.add_argument("--provider", choices=["auto", "nft", "winfw", "pf"], default="auto")
    ap.add_argument("--dump-plan", action="store_true", help="print plan text/commands")
    args = ap.parse_args(argv)

    pol = policy_from_env()
    opts = CompileOptions(dry_run=not args.apply, allow_exec=args.apply)
    eng = MicrosegEngine(opts)

    prov: Optional[FirewallProvider] = None
    if args.provider == "nft":
        prov = NftablesProvider(opts)
    elif args.provider == "winfw":
        prov = WindowsFirewallProvider(opts)
    elif args.provider == "pf":
        prov = PfProvider(opts)

    res = eng.compile(pol, provider=prov)
    if args.dump_plan:
        if res.provider == "nftables":
            print(eng._render_nft_plan(pol))
        else:
            for c in res.commands:
                print(" ".join(shlex.quote(x) for x in c.cmd))
    if args.apply:
        eng.apply(pol, allow_exec=True, provider=prov)
    else:
        logger.info("Dry-run. provider=%s plan_hash=%s issues=%s", res.provider, res.plan_hash, res.issues)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main(sys.argv[1:]))
