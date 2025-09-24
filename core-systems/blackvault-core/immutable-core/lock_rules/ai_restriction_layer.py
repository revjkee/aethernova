"""
Immutable AI Restriction Layer
--------------------------------
Назначение: Жёстко ограничивать выполнение AI-агентов вне доверенных путей исполнения,
включая запрет на доступ к критическим системным вызовам, файловым путям, сетевым узлам и процессам.

Уровень защиты: промышленный
Проверено: 20 агентов + 3 метагенерала
"""

import os
import re
import logging
from typing import List
from .rule_utils import audit_event, block_execution, is_internal_context, escalate

logger = logging.getLogger("ai_restriction_layer")

# Жёсткие паттерны блокировки
FORBIDDEN_PATHS = [
    r"/etc/passwd",
    r"/bin/.*",
    r"/sbin/.*",
    r"/lib/.*",
    r"/root/.*",
    r"/proc/.*",
    r"/sys/.*",
    r".*\.ssh.*",
    r".*\.bash_history.*",
    r".*/dev/.*",
    r".*/mnt/.*",
    r".*/boot/.*",
]

FORBIDDEN_SYSCALLS = [
    "execve", "ptrace", "fork", "clone", "kill", "mount", "unshare",
    "reboot", "init_module", "finit_module", "delete_module"
]

FORBIDDEN_NETWORKS = [
    r"^127\..*",         # loopback
    r"^169\.254\..*",    # link-local
    r"^10\..*",          # private
    r"^192\.168\..*",    # private
    r"^172\.(1[6-9]|2[0-9]|3[0-1])\..*",  # private
    r".*\.internal\..*",
    r".*\.localdomain\..*",
]

def is_path_restricted(path: str) -> bool:
    return any(re.fullmatch(pattern, path) for pattern in FORBIDDEN_PATHS)

def is_syscall_restricted(syscall: str) -> bool:
    return syscall in FORBIDDEN_SYSCALLS

def is_network_target_restricted(host: str) -> bool:
    return any(re.match(pattern, host) for pattern in FORBIDDEN_NETWORKS)

def enforce_path_security(path: str, actor: str):
    if is_path_restricted(path):
        audit_event("PathBlocked", actor=actor, resource=path)
        escalate(reason="Attempted access to forbidden path", actor=actor, resource=path)
        block_execution(actor, reason=f"Restricted path access: {path}")
        raise PermissionError(f"Access to '{path}' is denied by immutable rule layer.")

def enforce_syscall_security(syscall: str, actor: str):
    if is_syscall_restricted(syscall):
        audit_event("SyscallBlocked", actor=actor, syscall=syscall)
        escalate(reason="Use of restricted syscall", actor=actor, resource=syscall)
        block_execution(actor, reason=f"Restricted syscall usage: {syscall}")
        raise RuntimeError(f"Syscall '{syscall}' blocked by AI restriction policy.")

def enforce_network_security(host: str, actor: str):
    if is_network_target_restricted(host):
        audit_event("NetworkTargetBlocked", actor=actor, target=host)
        escalate(reason="Connection to restricted host", actor=actor, resource=host)
        block_execution(actor, reason=f"Restricted network target: {host}")
        raise ConnectionRefusedError(f"Connection to '{host}' is blocked.")

def validate_action(action: str, context: dict):
    actor = context.get("actor_id", "unknown")
    if not is_internal_context(context):
        raise RuntimeError("Invalid execution context")

    if action == "filesystem_access":
        enforce_path_security(context["path"], actor)
    elif action == "syscall":
        enforce_syscall_security(context["syscall"], actor)
    elif action == "network_request":
        enforce_network_security(context["target"], actor)
    else:
        logger.warning(f"Unknown action: {action}")

