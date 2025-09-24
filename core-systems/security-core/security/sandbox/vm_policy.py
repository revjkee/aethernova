# security-core/security/sandbox/vm_policy.py
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field, RootModel, ValidationError, field_validator

logger = logging.getLogger("security_core.sandbox.vm_policy")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Core models
# -----------------------------------------------------------------------------

class ResourceLimits(BaseModel):
    vcpu_count: int = Field(ge=1, le=128, default=1)
    cpu_quota_us: Optional[int] = Field(default=None, ge=1000)  # microseconds/period (100000 by default period)
    cpu_period_us: int = Field(default=100000, ge=1000)
    mem_bytes: int = Field(ge=64 * 1024 * 1024, default=512 * 1024 * 1024)  # >= 64 MiB
    swap_bytes: int = Field(default=0, ge=0)
    pids_max: int = Field(default=256, ge=32)
    nofile_soft: int = Field(default=4096, ge=128)
    nofile_hard: int = Field(default=8192, ge=256)
    cpu_shares: Optional[int] = Field(default=None, ge=2)
    oom_kill_disable: bool = Field(default=False)

class Mount(BaseModel):
    source: str
    target: str
    fstype: str = "bind"  # bind, tmpfs, proc, sysfs, devpts, etc.
    options: List[str] = Field(default_factory=list)
    readonly: bool = True

    @field_validator("target")
    @classmethod
    def _absolute_target(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("mount target must be absolute path")
        return v

class FilesystemPolicy(BaseModel):
    rootfs_path: str
    rootfs_readonly: bool = True
    mounts: List[Mount] = Field(default_factory=list)
    ensure_tmpfs_tmp: bool = True
    ensure_tmpfs_devshm: bool = True
    tmp_size_mb: int = Field(default=64, ge=4)
    devshm_size_mb: int = Field(default=64, ge=4)

class DeviceNode(BaseModel):
    path: str
    typ: Literal["c", "b"]  # char/block
    major: int
    minor: int
    file_mode: int = 0o666
    allow: bool = True

class DevicePolicy(BaseModel):
    allow_default: bool = False
    devices: List[DeviceNode] = Field(
        default_factory=lambda: [
            DeviceNode(path="/dev/null", typ="c", major=1, minor=3),
            DeviceNode(path="/dev/zero", typ="c", major=1, minor=5),
            DeviceNode(path="/dev/full", typ="c", major=1, minor=7),
            DeviceNode(path="/dev/random", typ="c", major=1, minor=8),
            DeviceNode(path="/dev/urandom", typ="c", major=1, minor=9),
            DeviceNode(path="/dev/tty", typ="c", major=5, minor=0, file_mode=0o622),
        ]
    )

class CapabilityPolicy(BaseModel):
    drop_all: bool = True
    allow: List[str] = Field(default_factory=list)  # e.g., ["CAP_NET_BIND_SERVICE"]

class NetworkRule(BaseModel):
    action: Literal["allow", "deny"]
    cidr: str
    ports: Optional[List[int]] = None  # None => any port
    proto: Optional[Literal["tcp", "udp", "icmp", "any"]] = "any"

    @field_validator("cidr")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        ip_network(v, strict=False)  # raises if invalid
        return v

class NetworkPolicy(BaseModel):
    enable_network: bool = False
    allow_dns: bool = True
    allowed_egress: List[NetworkRule] = Field(default_factory=list)
    denied_egress: List[NetworkRule] = Field(default_factory=list)
    # Hint flags for runtime adapters:
    isolate_macvlan: bool = False
    disable_ipv6: bool = True

class SyscallArgRule(BaseModel):
    index: int
    op: Literal[
        "SCMP_CMP_EQ", "SCMP_CMP_NE", "SCMP_CMP_LT", "SCMP_CMP_LE",
        "SCMP_CMP_GT", "SCMP_CMP_GE", "SCMP_CMP_MASKED_EQ"
    ]
    value: int
    valueTwo: Optional[int] = None

class SyscallRule(BaseModel):
    names: List[str]
    action: Literal["SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_TRAP"] = "SCMP_ACT_ALLOW"
    args: List[SyscallArgRule] = Field(default_factory=list)

class SeccompPolicy(BaseModel):
    default_action: Literal["SCMP_ACT_ERRNO", "SCMP_ACT_KILL"] = "SCMP_ACT_ERRNO"
    archs: List[str] = Field(default_factory=lambda: ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"])
    syscalls: List[SyscallRule] = Field(default_factory=list)

class VMIntegrity(BaseModel):
    masked_paths: List[str] = Field(default_factory=lambda: [
        "/proc/kcore", "/proc/keys", "/proc/sysrq-trigger", "/proc/timer_list", "/proc/sched_debug",
        "/sys/firmware", "/sys/fs/bpf"
    ])
    readonly_paths: List[str] = Field(default_factory=lambda: [
        "/proc", "/sys", "/etc"
    ])

class VMPolicy(BaseModel):
    name: str = "default"
    resources: ResourceLimits = ResourceLimits()
    fs: FilesystemPolicy
    devices: DevicePolicy = DevicePolicy()
    capabilities: CapabilityPolicy = CapabilityPolicy()
    network: NetworkPolicy = NetworkPolicy()
    seccomp: SeccompPolicy = SeccompPolicy()
    integrity: VMIntegrity = VMIntegrity()
    env_whitelist: List[str] = Field(default_factory=lambda: ["LANG", "LC_ALL", "TZ"])
    working_dir: str = "/"
    umask: int = Field(default=0o077, ge=0, le=0o777)

    @field_validator("working_dir")
    @classmethod
    def _wd_abs(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("working_dir must be absolute")
        return v

    def strict_validate(self) -> None:
        """
        Enforce strong assumptions for isolation.
        Raises ValidationError(ValueError) on violation.
        """
        errors: List[str] = []

        if not self.fs.rootfs_path or not str(self.fs.rootfs_path).strip():
            errors.append("rootfs_path must be set")

        if not self.fs.rootfs_readonly:
            errors.append("rootfs must be readonly for strict profiles")

        if self.capabilities.drop_all is False and self.capabilities.allow:
            # still acceptable, but warn if privileged caps are present
            sensitive = {"CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_TIME"}
            if any(c in sensitive for c in self.capabilities.allow):
                errors.append("sensitive capabilities present; drop them or isolate via full VM")

        if self.resources.mem_bytes < 64 * 1024 * 1024:
            errors.append("mem_bytes below 64MiB not allowed")

        # temporary filesystems must be noexec,nodev,nosuid
        if self.fs.ensure_tmpfs_tmp:
            opts = set(["noexec", "nodev", "nosuid"])
            if not opts.issubset(set(["noexec", "nodev", "nosuid", "size={}m".format(self.fs.tmp_size_mb)])):
                errors.append("/tmp tmpfs options must include noexec,nodev,nosuid")

        # seccomp must deny by default
        if self.seccomp.default_action != "SCMP_ACT_ERRNO" and self.seccomp.default_action != "SCMP_ACT_KILL":
            errors.append("seccomp default must deny (ERRNO or KILL)")

        if errors:
            raise ValueError("; ".join(errors))

# -----------------------------------------------------------------------------
# Presets
# -----------------------------------------------------------------------------

def _baseline_syscalls(minimal_fs: bool = True, allow_fork: bool = False, allow_net: bool = False) -> List[SyscallRule]:
    """
    Safe baseline for glibc/musl userspace without privileged operations.
    This is intentionally conservative.
    """
    base = [
        SyscallRule(names=["read", "write", "close", "fstat", "lseek", "mmap", "mprotect", "munmap",
                           "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "pread64",
                           "pwrite64", "clock_gettime", "nanosleep", "getpid", "gettid", "tgkill",
                           "getrandom", "set_robust_list", "futex", "sched_yield",
                           "arch_prctl", "prlimit64", "dup", "dup2", "dup3",
                           "fcntl", "stat", "lstat", "statx", "openat", "close_range",
                           "pipe2", "eventfd2", "timerfd_create", "timerfd_settime",
                           "epoll_create1", "epoll_ctl", "epoll_pwait", "poll", "ppoll",
                           "readlink", "readlinkat", "uname", "getcwd"],
                   action="SCMP_ACT_ALLOW"),
    ]
    if allow_fork:
        base.append(SyscallRule(names=["clone", "clone3", "fork", "vfork", "execve", "execveat"], action="SCMP_ACT_ALLOW"))
    else:
        base.append(SyscallRule(names=["execve", "execveat"], action="SCMP_ACT_ALLOW"))
    # FS ops if minimal_fs is False (allow mkdir/unlink/rename etc.)
    if not minimal_fs:
        base.append(SyscallRule(names=["mkdir", "mkdirat", "unlink", "unlinkat", "rename", "renameat", "renameat2",
                                       "chmod", "fchmod", "fchmodat", "chown", "lchown", "fchown", "fchownat",
                                       "utime", "utimes", "utimensat"], action="SCMP_ACT_ALLOW"))
    # Networking (optional)
    if allow_net:
        base.append(SyscallRule(names=["socket", "connect", "getsockopt", "setsockopt", "recvfrom", "sendto",
                                       "recvmsg", "sendmsg", "shutdown", "bind", "listen", "accept4", "getsockname",
                                       "getpeername", "getsockopt"], action="SCMP_ACT_ALLOW"))
        # DNS lookups via /etc/resolv.conf => openat already permitted
    # Random/cpu/aux
    base.append(SyscallRule(names=["getrlimit", "set_tid_address"], action="SCMP_ACT_ALLOW"))
    # deny dangerous by default (handled via default_action)
    return base

def preset_locked_down(rootfs_path: str) -> VMPolicy:
    mounts = [
        Mount(source="none", target="/tmp", fstype="tmpfs",
              options=[f"size=64m", "noexec", "nosuid", "nodev"], readonly=False),
        Mount(source="none", target="/dev/shm", fstype="tmpfs",
              options=[f"size=64m", "noexec", "nosuid", "nodev"], readonly=False),
        Mount(source="/proc", target="/proc", fstype="proc", options=["nosuid", "nodev", "noexec"], readonly=True),
        Mount(source="/sys", target="/sys", fstype="sysfs", options=["ro"], readonly=True),
    ]
    sec = SeccompPolicy(
        default_action="SCMP_ACT_ERRNO",
        syscalls=_baseline_syscalls(minimal_fs=True, allow_fork=False, allow_net=False),
    )
    pol = VMPolicy(
        name="locked_down",
        resources=ResourceLimits(),
        fs=FilesystemPolicy(rootfs_path=rootfs_path, rootfs_readonly=True, mounts=mounts),
        capabilities=CapabilityPolicy(drop_all=True, allow=[]),
        network=NetworkPolicy(enable_network=False),
        seccomp=sec,
    )
    pol.strict_validate()
    return pol

def preset_networked_batch(rootfs_path: str) -> VMPolicy:
    mounts = [
        Mount(source="none", target="/tmp", fstype="tmpfs",
              options=[f"size=256m", "noexec", "nosuid", "nodev"], readonly=False),
        Mount(source="none", target="/dev/shm", fstype="tmpfs",
              options=[f"size=128m", "noexec", "nosuid", "nodev"], readonly=False),
        Mount(source="/proc", target="/proc", fstype="proc", options=["nosuid", "nodev", "noexec"], readonly=True),
        Mount(source="/sys", target="/sys", fstype="sysfs", options=["ro"], readonly=True),
    ]
    sec = SeccompPolicy(
        default_action="SCMP_ACT_ERRNO",
        syscalls=_baseline_syscalls(minimal_fs=False, allow_fork=True, allow_net=True),
    )
    net = NetworkPolicy(
        enable_network=True,
        allow_dns=True,
        allowed_egress=[NetworkRule(action="allow", cidr="0.0.0.0/0")],
        denied_egress=[NetworkRule(action="deny", cidr="10.0.0.0/8")],
        isolate_macvlan=False,
        disable_ipv6=True,
    )
    pol = VMPolicy(
        name="networked_batch",
        resources=ResourceLimits(vcpu_count=2, mem_bytes=1024 * 1024 * 1024, pids_max=512),
        fs=FilesystemPolicy(rootfs_path=rootfs_path, rootfs_readonly=True, mounts=mounts),
        capabilities=CapabilityPolicy(drop_all=True, allow=["CAP_NET_BIND_SERVICE"]),
        network=net,
        seccomp=sec,
    )
    pol.strict_validate()
    return pol

def preset_python_restricted(rootfs_path: str) -> VMPolicy:
    """
    Сценарий для интерпретатора Python без сети, с возможностью порождать подпроцессы ограниченно.
    """
    sec = SeccompPolicy(
        default_action="SCMP_ACT_ERRNO",
        syscalls=_baseline_syscalls(minimal_fs=False, allow_fork=True, allow_net=False)
        + [
            SyscallRule(names=["rt_sigqueueinfo", "sigaltstack"], action="SCMP_ACT_ALLOW"),
            SyscallRule(names=["getdents64"], action="SCMP_ACT_ALLOW"),
        ],
    )
    mounts = [
        Mount(source="none", target="/tmp", fstype="tmpfs",
              options=[f"size=256m", "noexec", "nosuid", "nodev"], readonly=False),
        Mount(source="none", target="/dev/shm", fstype="tmpfs",
              options=[f"size=128m", "noexec", "nosuid", "nodev"], readonly=False),
        Mount(source="/proc", target="/proc", fstype="proc", options=["nosuid", "nodev", "noexec"], readonly=True),
        Mount(source="/sys", target="/sys", fstype="sysfs", options=["ro"], readonly=True),
    ]
    pol = VMPolicy(
        name="python_restricted",
        resources=ResourceLimits(vcpu_count=2, mem_bytes=1536 * 1024 * 1024, pids_max=512),
        fs=FilesystemPolicy(rootfs_path=rootfs_path, rootfs_readonly=True, mounts=mounts),
        capabilities=CapabilityPolicy(drop_all=True, allow=[]),
        network=NetworkPolicy(enable_network=False),
        seccomp=sec,
    )
    pol.strict_validate()
    return pol

# -----------------------------------------------------------------------------
# Exporters
# -----------------------------------------------------------------------------

def to_seccomp_json(policy: VMPolicy) -> Dict[str, Any]:
    """
    Convert policy.seccomp to docker-compatible seccomp JSON.
    """
    return {
        "defaultAction": policy.seccomp.default_action,
        "archMap": [{"architecture": a, "subarchitectures": []} for a in policy.seccomp.archs],
        "syscalls": [
            {
                "names": r.names,
                "action": r.action,
                "args": [
                    {"index": a.index, "op": a.op, "value": a.value, **({"valueTwo": a.valueTwo} if a.valueTwo is not None else {})}
                    for a in r.args
                ],
            }
            for r in policy.seccomp.syscalls
        ],
    }

def to_oci_linux_resources(policy: VMPolicy) -> Dict[str, Any]:
    """
    Partial OCI runtime spec: Linux resources + rlimits.
    """
    cpu = {}
    if policy.resources.cpu_quota_us is not None:
        cpu["quota"] = policy.resources.cpu_quota_us
        cpu["period"] = policy.resources.cpu_period_us
    if policy.resources.cpu_shares is not None:
        cpu["shares"] = policy.resources.cpu_shares

    resources = {
        "memory": {"limit": policy.resources.mem_bytes, "swap": policy.resources.swap_bytes},
        "cpu": cpu,
        "pids": {"limit": policy.resources.pids_max},
        "devices": [
            {"allow": d.allow, "type": d.typ, "major": d.major, "minor": d.minor, "access": "rwm", "fileMode": d.file_mode}
            for d in policy.devices.devices
        ],
    }
    rlimits = [
        {"type": "RLIMIT_NOFILE", "hard": policy.resources.nofile_hard, "soft": policy.resources.nofile_soft},
    ]
    return {"linux": {"resources": resources}, "process": {"rlimits": rlimits}}

def to_oci_mounts(policy: VMPolicy) -> List[Dict[str, Any]]:
    mounts = []
    # rootfs is handled by runtime; we add extra mounts
    for m in policy.fs.mounts:
        ent = {"destination": m.target, "type": m.fstype, "source": m.source, "options": list(m.options)}
        if m.readonly and "ro" not in ent["options"]:
            ent["options"].append("ro")
        mounts.append(ent)
    # Ensure tmpfs for /tmp,/dev/shm if requested
    if policy.fs.ensure_tmpfs_tmp and not any(x["destination"] == "/tmp" for x in mounts):
        mounts.append({"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
                       "options": [f"size={policy.fs.tmp_size_mb}m", "noexec", "nosuid", "nodev"]})
    if policy.fs.ensure_tmpfs_devshm and not any(x["destination"] == "/dev/shm" for x in mounts):
        mounts.append({"destination": "/dev/shm", "type": "tmpfs", "source": "tmpfs",
                       "options": [f"size={policy.fs.devshm_size_mb}m", "noexec", "nosuid", "nodev"]})
    return mounts

def to_oci_process(policy: VMPolicy) -> Dict[str, Any]:
    env = [f"{k}={os.environ.get(k, '')}" for k in policy.env_whitelist if k in os.environ]
    caps = {
        "bounding": policy.capabilities.allow if not policy.capabilities.drop_all else [],
        "effective": policy.capabilities.allow if not policy.capabilities.drop_all else [],
        "inheritable": policy.capabilities.allow if not policy.capabilities.drop_all else [],
        "permitted": policy.capabilities.allow if not policy.capabilities.drop_all else [],
        "ambient": [],
    }
    return {"cwd": policy.working_dir, "env": env, "user": {"uid": 1000, "gid": 1000}, "capabilities": caps, "umask": policy.umask}

@dataclass
class LaunchPlan:
    """
    Абстрактный план запуска microVM/контейнера.
    Адаптеры конкретных рантаймов могут использовать эти поля.
    """
    kernel_image: Optional[str]
    kernel_cmdline: str
    rootfs: str
    rootfs_readonly: bool
    vcpu_count: int
    mem_mib: int
    net_enabled: bool
    vsock_cid: Optional[int] = None  # если используется vsock
    metadata: Dict[str, Any] = None

def to_launch_plan(policy: VMPolicy, kernel_image: Optional[str] = None, kernel_cmdline: Optional[str] = None) -> LaunchPlan:
    cmdline = kernel_cmdline or "console=ttyS0 nohibernate mitigations=on panic=1"
    return LaunchPlan(
        kernel_image=kernel_image,
        kernel_cmdline=cmdline,
        rootfs=policy.fs.rootfs_path,
        rootfs_readonly=policy.fs.rootfs_readonly,
        vcpu_count=policy.resources.vcpu_count,
        mem_mib=policy.resources.mem_bytes // (1024 * 1024),
        net_enabled=policy.network.enable_network,
        metadata={
            "seccomp_default": policy.seccomp.default_action,
            "caps_drop_all": policy.capabilities.drop_all,
            "readonly_paths": policy.integrity.readonly_paths,
            "masked_paths": policy.integrity.masked_paths,
            "name": policy.name,
        },
    )

# -----------------------------------------------------------------------------
# Helpers for file output
# -----------------------------------------------------------------------------

def save_seccomp_json(policy: VMPolicy, path: str) -> None:
    data = to_seccomp_json(policy)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    logger.info("seccomp profile written to %s", path)

def save_oci_fragments(policy: VMPolicy, dir_path: str) -> Tuple[str, str, str]:
    """
    Сохраняет три файла: linux_resources.json, mounts.json, process.json.
    Возвращает пути.
    """
    d = Path(dir_path)
    d.mkdir(parents=True, exist_ok=True)
    p1 = d / "linux_resources.json"
    p2 = d / "mounts.json"
    p3 = d / "process.json"
    with open(p1, "w", encoding="utf-8") as f:
        json.dump(to_oci_linux_resources(policy), f, ensure_ascii=False, indent=2)
    with open(p2, "w", encoding="utf-8") as f:
        json.dump(to_oci_mounts(policy), f, ensure_ascii=False, indent=2)
    with open(p3, "w", encoding="utf-8") as f:
        json.dump(to_oci_process(policy), f, ensure_ascii=False, indent=2)
    logger.info("oci fragments written to %s", d)
    return str(p1), str(p2), str(p3)

# -----------------------------------------------------------------------------
# Example usage (manual)
# -----------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    # 1) Locked-down microVM with readonly rootfs
    pol = preset_locked_down(rootfs_path="/var/lib/vm-images/min-rootfs.ext4")
    save_seccomp_json(pol, "./_out/seccomp_locked_down.json")
    save_oci_fragments(pol, "./_out/oci_locked_down")

    # 2) Networked batch preset
    pol2 = preset_networked_batch(rootfs_path="/var/lib/vm-images/batch-rootfs.ext4")
    save_seccomp_json(pol2, "./_out/seccomp_batch.json")
    save_oci_fragments(pol2, "./_out/oci_batch")

    # 3) Python restricted preset
    pol3 = preset_python_restricted(rootfs_path="/var/lib/vm-images/python-rootfs.ext4")
    save_seccomp_json(pol3, "./_out/seccomp_python.json")
    save_oci_fragments(pol3, "./_out/oci_python")
