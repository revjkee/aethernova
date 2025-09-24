# core-systems/avm_core/tests/test_vpn.py
from __future__ import annotations

import os
import textwrap
from pathlib import Path
from typing import List, Tuple

import pytest

# Модули для теста
import avm_core.vpn.vpn_manager as vm


@pytest.fixture(autouse=True)
def _env_secrets(monkeypatch):
    # Секреты для wireguard.yaml (vault:// ссылки читаются через ENV в провайдере)
    monkeypatch.setenv("AVM_WG_PRIVKEY", "TEST_PRIVATE_KEY")
    monkeypatch.setenv("AVM_WG_PSK", "TEST_PSK")
    yield


@pytest.fixture()
def wg_configs(tmp_path: Path) -> Tuple[Path, Path]:
    """Создает временные profiles.yaml и wireguard.yaml."""
    profiles = tmp_path / "profiles.yaml"
    wireguard = tmp_path / "wireguard.yaml"

    profiles.write_text(
        textwrap.dedent(
            """
            apiVersion: avm/v1
            kind: NetworkProfiles
            default: "wireguard"
            profiles:
              wireguard:
                provider: "wireguard"
                iface: "avmwg0"
                enforce_killswitch: true
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    wireguard.write_text(
        textwrap.dedent(
            """
            apiVersion: avm/v1
            kind: WireGuardConfig
            iface: "avmwg0"
            addresses:
              - "10.7.0.2/32"
              - "fd00:7::2/128"
            endpoint: "vpn.example.com:51820"
            peer_public_key: "PEERPUB"
            private_key_ref: "vault://kv/core/avm/wg/private_key"
            preshared_key_ref: "vault://kv/core/avm/wg/psk"
            allowed_ips:
              - "0.0.0.0/0"
              - "::/0"
            persistent_keepalive: 25
            mtu: 1380
            killswitch:
              enabled: true
              backend: "iptables"
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return profiles, wireguard


@pytest.fixture()
def ovpn_profiles(tmp_path: Path) -> Path:
    """Создает временный profiles.yaml для OpenVPN."""
    ovpn_conf = tmp_path / "client.ovpn"
    ovpn_conf.write_text("# dummy openvpn config\n", encoding="utf-8")

    profiles = tmp_path / "profiles.yaml"
    profiles.write_text(
        textwrap.dedent(
            f"""
            apiVersion: avm/v1
            kind: NetworkProfiles
            default: "openvpn"
            profiles:
              openvpn:
                provider: "openvpn"
                config_path: "{ovpn_conf.as_posix()}"
                iface: "tun0"
                enforce_killswitch: true
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return profiles


@pytest.fixture()
def fake_runner(monkeypatch):
    """
    Подменяет vm._run на безопасный симулятор системных команд.
    Эмулируются ip/iptables/ip6tables/wg/openvpn/bash -lc и пр.
    """
    executed: List[str] = []

    def _fake_run(cmd: List[str], check: bool = True):
        nonlocal executed
        executed.append(" ".join(cmd))

        # iptables/ip6tables: разрешаем все операции
        if cmd[0] in ("iptables", "ip6tables"):
            if len(cmd) >= 3 and cmd[1] == "-S" and cmd[2] == "OUTPUT":
                # Вернем пустой список правил; менеджер вставит наш jump
                return (0, "", "")
            return (0, "", "")

        # bash -lc "ip{,6}tables ..." или "ip link del ..." и т.п.
        if cmd[0] == "bash":
            return (0, "", "")

        # wg set / show
        if cmd[0] == "wg":
            if len(cmd) >= 2 and cmd[1] == "show":
                iface = cmd[2] if len(cmd) > 2 else "avmwg0"
                out = textwrap.dedent(
                    f"""
                    interface: {iface}
                      public key: XXXXXXXXXXXXX
                      private key: (hidden)
                      listening port: 51820

                    peer: PEERPUB
                      endpoint: 203.0.113.10:51820
                      allowed ips: 0.0.0.0/0, ::/0
                      latest handshake: now
                      transfer: 1234 received, 5678 sent
                      persistent keepalive: every 25 seconds
                    """
                ).strip()
                return (0, out, "")
            # wg set ... — просто OK
            return (0, "", "")

        # ip link / address: все операции успешны
        if cmd[0] == "ip":
            return (0, "", "")

        # openvpn / pkill — симулируем успешный запуск/останов
        if cmd[0] == "openvpn":
            return (0, "", "")
        if cmd[0] == "pkill":
            return (0, "", "")

        # ip addr show tun0 — состояние интерфейса для OpenVPN
        if cmd[0] == "bash" and "ip addr show tun0" in " ".join(cmd):
            return (0, "inet 10.8.0.2/24 brd 10.8.0.255 scope global tun0", "")

        # по умолчанию: OK
        return (0, "", "")

    # Подмена низкоуровневых функций
    monkeypatch.setattr(vm, "_run", _fake_run, raising=True)
    monkeypatch.setattr(vm, "_ensure_root", lambda: None, raising=True)
    monkeypatch.setattr(vm, "time", __import__("time"))  # оставляем time как есть

    # Резолвинг endpoint в фиксированный IP:порт
    monkeypatch.setattr(vm, "_resolve_host", lambda ep: ("203.0.113.10", 51820, "ipv4"), raising=True)

    # Отключаем фоновый монитор (чтобы тесты были детерминированными)
    monkeypatch.setattr(vm.VpnManager, "_start_monitoring_thread", lambda self: None, raising=True)

    return executed


def test_wireguard_up_status_down(fake_runner, wg_configs, monkeypatch):
    profiles_path, wg_cfg_path = wg_configs

    # Создаем менеджер с временными конфигами
    m = vm.VpnManager(profiles_path=str(profiles_path), wg_cfg_path=str(wg_cfg_path))

    # Поднять профиль WireGuard
    st = m.up("wireguard")
    assert st.connected is True
    assert st.iface == "avmwg0"
    assert m._active_profile == "wireguard"
    assert m._killswitch.enabled is True  # pre/post режимы должны быть активированы

    # Проверить статус
    s = m.status()
    assert s["active"] is True
    assert s["status"]["connected"] is True
    assert s["status"]["iface"] == "avmwg0"

    # Снять VPN
    m.down()
    assert m._active_profile is None
    assert m._killswitch.enabled is False
    assert m.status()["active"] is False


def test_reconnect_flow_without_thread(fake_runner, wg_configs):
    """
    Проверяем, что ручной вызов реконнекта отрабатывает без исключений
    и повторно поднимает провайдера с активным kill‑switch.
    """
    profiles_path, wg_cfg_path = wg_configs
    m = vm.VpnManager(profiles_path=str(profiles_path), wg_cfg_path=str(wg_cfg_path))

    # up → затем принудительный _reconnect_locked
    m.up("wireguard")
    # Искусственно «сломаем» провайдера: заменим на новый класс, возвращающий корректный статус
    assert m._provider is not None
    m._reconnect_locked()  # не должен бросать исключение
    assert m._provider is not None
    assert m._killswitch.enabled is True
    assert m.status()["active"] is True


def test_openvpn_profile_up_status(fake_runner, ovpn_profiles):
    """
    Минимальная проверка OpenVPN-провайдера: успешный up(), статус с интерфейсом tun0.
    """
    profiles_path = ovpn_profiles
    # Для OpenVPN WireGuard-конфиг не используется, передаем любой валидный путь
    m = vm.VpnManager(profiles_path=str(profiles_path), wg_cfg_path=str(profiles_path))

    st = m.up("openvpn")
    assert st.provider == "openvpn"
    assert st.iface == "tun0"
    # Статус менеджера
    s = m.status()
    assert s["active"] is True
    assert s["status"]["provider"] == "openvpn"

    m.down()
    assert m.status()["active"] is False
