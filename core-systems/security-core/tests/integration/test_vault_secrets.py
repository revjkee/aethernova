# security-core/tests/integration/test_vault_secrets.py
# Интеграционные тесты HashiCorp Vault: KV v2 и Transit.
# Требует запущенный Vault и hvac. Тесты скипаются, если окружение не готово.
from __future__ import annotations

import base64
import os
import time
import uuid
from contextlib import suppress

import pytest

try:
    import hvac  # type: ignore
except Exception:  # hvac не установлен
    hvac = None  # type: ignore

pytestmark = pytest.mark.integration


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64ed(b: bytes) -> str:
    # base64-encode with "deterministic" wording for clarity
    return base64.b64encode(b).decode("ascii")


def _require_env(var: str) -> str | None:
    v = os.getenv(var)
    return v if v and v.strip() else None


def _skip_reason_env() -> str | None:
    if hvac is None:
        return "hvac package not installed"
    if not _require_env("VAULT_ADDR"):
        return "VAULT_ADDR is not set"
    if not _require_env("VAULT_TOKEN"):
        return "VAULT_TOKEN is not set"
    return None


@pytest.fixture(scope="session")
def vault_client():
    reason = _skip_reason_env()
    if reason:
        pytest.skip(reason)
    addr = os.environ["VAULT_ADDR"]
    token = os.environ["VAULT_TOKEN"]
    namespace = os.getenv("VAULT_NAMESPACE")
    client = hvac.Client(url=addr, token=token, namespace=namespace)  # type: ignore
    if not client.is_authenticated():
        pytest.skip("Vault: authentication failed with provided token")
    return client


@pytest.fixture(scope="session")
def kv2_mount(vault_client):
    """
    Создает временный KV v2 mount (например, kv-ci-<uuid>) и удаляет его в конце.
    Если mount уже существует (редкий случай), переиспользует.
    """
    sys = vault_client.sys
    mount = f"kv-ci-{uuid.uuid4().hex[:8]}"
    # enable KV v2
    with suppress(Exception):
        sys.enable_secrets_engine(
            backend_type="kv",
            path=mount,
            options={"version": "2"},
            description="CI KV v2 mount for security-core tests",
        )
    try:
        mounts = sys.list_mounted_secrets_engines().get("data", {})  # type: ignore
    except Exception:
        mounts = sys.list_mounted_secrets_engines()  # older hvac returns dict directly
    assert f"{mount}/" in mounts, "KV v2 mount not present after enabling"
    yield mount
    # teardown
    with suppress(Exception):
        sys.disable_secrets_engine(path=mount)


@pytest.fixture(scope="session")
def transit_ready(vault_client):
    """
    Обеспечивает включенный Transit secrets engine (на /transit). Если нет прав — скип.
    """
    sys = vault_client.sys
    try:
        mounts = sys.list_mounted_secrets_engines()
        if "transit/" not in (mounts.get("data") or mounts):  # tolerate versions
            sys.enable_secrets_engine("transit")
    except Exception as e:
        pytest.skip(f"Transit engine not available or cannot be enabled: {e}")
    return "transit"


# ------------------------------
# KV v2: запись/чтение/версии/CAS
# ------------------------------

def test_kv_v2_write_read_and_cas(vault_client, kv2_mount):
    kv = vault_client.secrets.kv.v2
    path = f"security-core/tests/{uuid.uuid4().hex}"
    secret_v1 = {"username": "svc_user", "pass": "P@ssw0rd", "flag": True}
    # create v1
    kv.create_or_update_secret(mount_point=kv2_mount, path=path, secret=secret_v1)
    r1 = kv.read_secret_version(mount_point=kv2_mount, path=path)
    v1 = int(r1["data"]["metadata"]["version"])
    assert v1 >= 1
    assert r1["data"]["data"]["username"] == "svc_user"

    # update v2 with CAS (must succeed when cas=version)
    secret_v2 = {"username": "svc_user", "pass": "N3w", "roles": ["reader", "writer"]}
    kv.create_or_update_secret(mount_point=kv2_mount, path=path, secret=secret_v2, cas=v1)
    r2 = kv.read_secret_version(mount_point=kv2_mount, path=path)
    v2 = int(r2["data"]["metadata"]["version"])
    assert v2 == v1 + 1
    assert r2["data"]["data"]["pass"] == "N3w"
    assert r2["data"]["data"]["roles"] == ["reader", "writer"]

    # CAS mismatch should fail (optimistic lock)
    with pytest.raises(Exception):
        kv.create_or_update_secret(mount_point=kv2_mount, path=path, secret={"x": 1}, cas=v1)  # stale CAS

    # read specific version v1
    r_old = kv.read_secret_version(mount_point=kv2_mount, path=path, version=v1)
    assert r_old["data"]["data"]["flag"] is True

    # cleanup secret (delete latest version only)
    vault_client.secrets.kv.v2.delete_latest_version_of_secret(mount_point=kv2_mount, path=path)  # type: ignore


# ------------------------------
# Transit: encrypt/decrypt/sign/verify
# ------------------------------

def test_transit_encrypt_decrypt_and_sign_verify(vault_client, transit_ready):
    trans = vault_client.secrets.transit
    key_name = f"sc-ci-{uuid.uuid4().hex[:10]}"
    # Create key (ed25519 for sign/verify; encryption uses symmetric via transit)
    trans.create_key(name=key_name, type="ed25519", exportable=False)  # type: ignore

    try:
        plaintext = b"top-secret:42"
        context = b"security-core:test"  # AAD context for stronger bound
        # Encrypt (plaintext must be base64)
        enc = trans.encrypt_data(name=key_name, plaintext=_b64e(plaintext), context=_b64e(context))
        ct = enc["data"]["ciphertext"]
        assert ct.startswith("vault:v")

        # Decrypt
        dec = trans.decrypt_data(name=key_name, ciphertext=ct, context=_b64e(context))
        out = base64.b64decode(dec["data"]["plaintext"])
        assert out == plaintext

        # Sign (Transit signs over input; we pass base64/plain)
        msg = b"integrity-check"
        sresp = trans.sign_data(name=key_name, hash_algorithm="sha2-256", input=_b64e(msg))  # type: ignore
        sig = sresp["data"]["signature"]
        assert sig.startswith(f"vault:v1:{key_name}:")
        # Verify
        vresp = trans.verify_signed_data(name=key_name, hash_algorithm="sha2-256", input=_b64e(msg), signature=sig)  # type: ignore
        assert bool(vresp["data"]["valid"]) is True

        # Wrong message must not verify
        vbad = trans.verify_signed_data(name=key_name, hash_algorithm="sha2-256", input=_b64e(b"wrong"), signature=sig)  # type: ignore
        assert bool(vbad["data"]["valid"]) is False
    finally:
        # Allow deletion and remove key material
        with suppress(Exception):
            trans.update_key_configuration(name=key_name, deletion_allowed=True)  # type: ignore
        with suppress(Exception):
            trans.delete_key(name=key_name)  # type: ignore


# ------------------------------
# Token basics (lookup-self)
# ------------------------------

def test_token_lookup_self_has_info(vault_client):
    info = vault_client.auth.token.lookup_self()  # type: ignore
    data = info.get("data") or info  # tolerate older hvac
    assert "id" in (data.get("id") or data.get("accessor") or {})
    # TTL может быть 0 (root/dev режим) — проверяем тип и наличие
    ttl = data.get("ttl")
    assert ttl is None or isinstance(ttl, int)


# ------------------------------
# Optional: AppRole authentication (skipped if env not set)
# ------------------------------

@pytest.mark.skipif(not _require_env("VAULT_ROLE_ID") or not _require_env("VAULT_SECRET_ID"), reason="AppRole env not provided")
def test_approle_auth_and_kv_access(vault_client, kv2_mount):
    """
    Проверяет, что AppRole‑аутентификация выдает рабочий токен с доступом к KV.
    Требуемые переменные окружения:
      VAULT_ROLE_ID, VAULT_SECRET_ID
    Политика роли должна разрешать чтение/запись в mount kv2_mount.
    """
    role_id = os.environ["VAULT_ROLE_ID"]
    secret_id = os.environ["VAULT_SECRET_ID"]
    addr = os.environ["VAULT_ADDR"]
    namespace = os.getenv("VAULT_NAMESPACE")

    app_client = hvac.Client(url=addr, namespace=namespace)  # type: ignore
    login = app_client.auth.approle.login(role_id=role_id, secret_id=secret_id)  # type: ignore
    assert app_client.is_authenticated(), "AppRole login failed"

    # Попробуем записать/прочитать в наш mount
    path = f"approle-ci/{uuid.uuid4().hex}"
    kv = app_client.secrets.kv.v2
    kv.create_or_update_secret(mount_point=kv2_mount, path=path, secret={"ok": True})
    r = kv.read_secret_version(mount_point=kv2_mount, path=path)
    assert r["data"]["data"]["ok"] is True
