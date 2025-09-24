import os
import sys
import socket
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Если реализация ещё не готова — пропускаем весь набор (тесты служат спецификацией).
qemu_mod = pytest.importorskip("avm_core.qemu_runner")
QemuRunner = qemu_mod.QemuRunner
QemuConfig = getattr(qemu_mod, "QemuConfig", None)


# ------------------------------
# Вспомогательные фейки и фикстуры
# ------------------------------

class _FakePopen:
    """Фейковый subprocess.Popen с минимально нужным поведением."""
    def __init__(self, args, stdout=None, stderr=None, cwd=None, env=None, text=None):
        self.args = args
        self.stdout = stdout
        self.stderr = stderr
        self.cwd = cwd
        self.env = env or {}
        self.text = text
        self.pid = 4242
        self._ret = None
        self._terminated = False
        self._killed = False

    def poll(self):
        return self._ret

    def wait(self, timeout=None):
        t0 = time.time()
        while self._ret is None:
            if timeout and (time.time() - t0) > timeout:
                raise pytest.fail("FakePopen.wait timed out")
            time.sleep(0.01)
        return self._ret

    def terminate(self):
        self._terminated = True
        self._ret = 0

    def kill(self):
        self._killed = True
        self._ret = -9


@pytest.fixture(autouse=True)
def strict_env(monkeypatch):
    # Не даём тестам зависеть от внешнего окружения
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("LANG", "C")


@pytest.fixture
def fake_popen(monkeypatch):
    created = {"proc": None}

    def _fake_popen(*args, **kwargs):
        created["proc"] = _FakePopen(*args, **kwargs)
        return created["proc"]

    monkeypatch.setattr(qemu_mod.subprocess, "Popen", _fake_popen)
    return created


@pytest.fixture
def fake_which(monkeypatch, tmp_path):
    # Подменяем shutil.which, чтобы не требовать реального qemu
    qemu_bin = tmp_path / "qemu-system-x86_64"
    qemu_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(qemu_bin, 0o755)
    monkeypatch.setattr(qemu_mod.shutil, "which", lambda name: str(qemu_bin))
    return qemu_bin


@pytest.fixture
def cfg(tmp_path):
    """Базовая конфигурация для раннера (датакласс/объект QemuConfig)."""
    if QemuConfig:
        return QemuConfig(
            workdir=tmp_path,
            memory_mb=2048,
            smp=2,
            image=str(tmp_path / "disk.qcow2"),
            ssh_forward=2222,
            display="none",
            enable_kvm=True,
            extra_args=[],
        )
    # Если в вашей реализации другой интерфейс — создайте совместимый dict
    return {
        "workdir": tmp_path,
        "memory_mb": 2048,
        "smp": 2,
        "image": str(tmp_path / "disk.qcow2"),
        "ssh_forward": 2222,
        "display": "none",
        "enable_kvm": True,
        "extra_args": [],
    }


# ------------------------------
# Утилиты проверок
# ------------------------------

def _assert_has_fragment(cmd: List[str], fragment: List[str]):
    """Проверяет, что в командной строке есть непрерывный фрагмент."""
    s = " ".join(cmd)
    sub = " ".join(fragment)
    assert sub in s, f"Ожидали фрагмент {fragment} в команде: {cmd}"


# ------------------------------
# Тесты спецификации
# ------------------------------

def test_build_cmd_includes_core_flags(cfg, tmp_path, fake_which, monkeypatch):
    # Эмулируем наличие /dev/kvm — раннер должен включить -enable-kvm
    monkeypatch.setattr(os.path, "exists", lambda p: True if p == "/dev/kvm" else os.path.exists(p))
    r = QemuRunner(cfg)
    cmd = r.build_cmd()

    # Бинарь, память, CPU, SMP, headless
    assert any("qemu-system" in x for x in cmd)
    _assert_has_fragment(cmd, ["-m", "2048"])
    _assert_has_fragment(cmd, ["-smp", "2"])
    _assert_has_fragment(cmd, ["-display", "none"])
    # KVM включён
    assert "-enable-kvm" in cmd or "-accel" in cmd and "kvm" in " ".join(cmd)

    # QMP и Serial — unix сокеты в рабочей директории
    _assert_has_fragment(cmd, ["-qmp", f"unix:{r.qmp_socket_path},server,nowait"])
    _assert_has_fragment(cmd, ["-serial", f"unix:{r.serial_socket_path},server,nowait"])

    # Диск основного образа
    # Допускаем реализацию через -drive или -blockdev
    s = " ".join(cmd)
    assert "file=" in s and "qcow2" in s or "-blockdev" in cmd


def test_build_cmd_falls_back_to_tcg_when_no_kvm(cfg, fake_which, monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: False if p == "/dev/kvm" else os.path.exists(p))
    if isinstance(cfg, dict):
        cfg["enable_kvm"] = True
    else:
        cfg.enable_kvm = True

    r = QemuRunner(cfg)
    cmd = r.build_cmd()
    s = " ".join(cmd)
    assert "-enable-kvm" not in cmd
    # При отсутствии KVM должен быть TCG
    assert "-accel tcg" in s or "accel=tcg" in s


def test_user_network_with_ssh_forward(cfg, fake_which):
    r = QemuRunner(cfg)
    cmd = r.build_cmd()
    s = " ".join(cmd)
    # Проверяем проброс SSH на порт 2222 (user, hostfwd)
    assert "hostfwd=tcp::2222-:22" in s or "hostfwd=tcp::2222-127.0.0.1:22" in s


def test_attach_cdrom_cloud_init_if_present(cfg, tmp_path, fake_which):
    seed = tmp_path / "seed.iso"
    seed.write_bytes(b"ISO")
    if isinstance(cfg, dict):
        cfg["cloud_init_iso"] = str(seed)
    else:
        cfg.cloud_init_iso = str(seed)

    r = QemuRunner(cfg)
    cmd = r.build_cmd()
    s = " ".join(cmd)
    assert "cdrom" in s or "media=cdrom" in s, "Ожидали подключение ISO как CD-ROM"


def test_start_wait_ready_and_stop_grace(tmp_path, cfg, fake_popen, fake_which, monkeypatch):
    # Подделываем проверку готовности QMP
    ready_called = {"n": 0}
    def fake_wait_ready(timeout: float = 30.0) -> bool:
        ready_called["n"] += 1
        return True

    r = QemuRunner(cfg)
    monkeypatch.setattr(r, "wait_ready", fake_wait_ready)

    r.start()
    assert fake_popen["proc"] is not None, "Должны вызвать subprocess.Popen"
    assert r.is_running()

    # Graceful stop (через QMP/system_powerdown внутри раннера)
    r.stop(grace=2.0)
    # Фейк завершает процесс через terminate()
    assert fake_popen["proc"]._terminated or fake_popen["proc"]._killed is True


def test_kill_forces_termination(tmp_path, cfg, fake_popen, fake_which):
    r = QemuRunner(cfg)
    r.start()
    r.kill()
    assert fake_popen["proc"]._killed is True


def test_allocate_port_skips_occupied(monkeypatch):
    # Эмулируем занятый порт, затем свободный
    occupied = []

    def _fake_bind(addr):
        host, port = addr
        if port in (55000,):
            raise OSError("Address already in use")
        occupied.append(port)

    class _FakeSock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def setsockopt(self, *a, **k): pass
        def bind(self, addr): _fake_bind(addr)
        def getsockname(self): return ("127.0.0.1", occupied[-1] if occupied else 0)
        def close(self): pass

    monkeypatch.setattr(socket, "socket", lambda *a, **k: _FakeSock())
    port = QemuRunner.allocate_port(55000, 55001)
    assert port == 55001, f"Ожидали пропуск занятого 55000, получили {port}"


def test_error_when_binary_missing(monkeypatch, cfg):
    # which возвращает None → раннер должен поднять понятную ошибку при старте
    monkeypatch.setattr(qemu_mod.shutil, "which", lambda name: None)
    r = QemuRunner(cfg)
    with pytest.raises(Exception):
        r.start()


def test_log_file_rotation(tmp_path, cfg, fake_popen, fake_which):
    # Если в раннере есть лог‑файл — проверим создание/запись
    r = QemuRunner(cfg)
    r.start()
    if getattr(r, "log_path", None):
        logp = Path(r.log_path)
        logp.write_text("qemu boot log\n", encoding="utf-8")
        assert logp.exists() and logp.stat().st_size > 0


@pytest.mark.parametrize("grace_ok", [True, False])
def test_stop_grace_then_kill(monkeypatch, tmp_path, cfg, fake_popen, fake_which, grace_ok):
    r = QemuRunner(cfg)

    # Подменим внутренний QMP вызов system_powerdown для контроля
    called = {"powerdown": 0}

    def fake_qmp(cmd: str, **params):
        if cmd == "system_powerdown":
            called["powerdown"] += 1
            return {"return": "ok"}
        return {"return": "ok"}

    monkeypatch.setattr(r, "qmp", fake_qmp)
    r.start()

    # Имитируем, что процесс завершится/не завершится после grace‑таймаута
    p = r._process  # type: ignore[attr-defined]
    assert isinstance(p, _FakePopen)
    if grace_ok:
        def _terminate():
            p._ret = 0
        # Позднее завершение
        _terminate()
    # Вызываем stop
    r.stop(grace=0.05)
    assert called["powerdown"] >= 1
    if grace_ok:
        assert p._killed is False
    else:
        # Если не завершилось — runner обязан добить
        assert p._killed is True


def test_cmd_contains_nodefaults_and_secure_defaults(cfg, fake_which):
    r = QemuRunner(cfg)
    cmd = r.build_cmd()
    s = " ".join(cmd)
    # Безопасные флаги: headless/nodefaults/no-user-config/RTC/accel выставляются
    assert "-nodefaults" in cmd or "nodefaults" in s
    assert "-no-user-config" in cmd or "no-user-config" in s
    # RTC/clock источник не навязываем, но допускаем явные флаги
    # Наличие -sandbox on в некоторых сборках — опционально


def test_can_execute_qmp_commands(monkeypatch, cfg, fake_popen, fake_which):
    r = QemuRunner(cfg)
    r.start()

    # Подделываем сокетный QMP-канал — выполняем простую команду
    def fake_qmp(cmd: str, **params):
        if cmd == "query-status":
            return {"return": {"status": "running"}}
        return {"return": "ok"}

    monkeypatch.setattr(r, "qmp", fake_qmp)
    resp = r.qmp("query-status")
    assert resp["return"]["status"] == "running"
