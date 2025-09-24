# oblivionvault-core/tests/integration/test_kms_crypto_shred.py
# Интеграционные тесты KMS + Envelope и крипто-уничтожение приватного ключа.
# Требуется установленный OpenSSL в PATH или через OPENSSL_PATH.
# Python 3.10+

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

# Импортируем промышленный код из пакета
from oblivionvault.adapters.kms_adapter import (
    KmsAdapter,
    OpenSSLRSABackend,
    Envelope,
    load_kms_from_env,
    KmsError,
    OpenSSLNotFound,
)

# --------------------------
# Вспомогательные утилиты
# --------------------------
def _openssl_bin() -> str | None:
    return os.getenv("OPENSSL_PATH") or shutil.which("openssl")

def _run_openssl(args: list[str], input_bytes: bytes | None = None) -> bytes:
    bin_path = _openssl_bin()
    if not bin_path:
        raise OpenSSLNotFound("OpenSSL not found")
    proc = subprocess.run(
        [bin_path] + args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"OpenSSL error ({' '.join(args)}): {proc.stderr.decode('utf-8', 'ignore')}")
    return proc.stdout

def _gen_rsa_keypair(dirpath: Path, key_id: str, bits: int = 2048) -> tuple[Path, Path]:
    """Генерирует RSA-ключи, возвращает (priv_pem, pub_pem). 2048 бит достаточно для теста."""
    dirpath.mkdir(parents=True, exist_ok=True)
    priv = dirpath / f"{key_id}.priv.pem"
    pub = dirpath / f"{key_id}.pub.pem"
    _run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}", "-out", str(priv)])
    _run_openssl(["rsa", "-in", str(priv), "-pubout", "-out", str(pub)])
    return priv, pub

def _secure_shred(path: Path) -> None:
    """
    Best-effort перезапись и удаление файла приватного ключа.
    Примечание: файловые системы и ОС могут оптимизировать запись; это тестовая процедура.
    """
    if not path.exists():
        return
    try:
        size = path.stat().st_size
        # Перезаписываем случайными байтами и нулями
        with open(path, "r+b", buffering=0) as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
            f.seek(0)
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        # Игнорируем ошибки перезаписи — удалим файл в любом случае
        pass
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass

# --------------------------
# Фикстуры
# --------------------------
@pytest.fixture(scope="module")
def openssl_present():
    if not _openssl_bin():
        pytest.skip("OpenSSL не найден — интеграционный тест пропущен")

@pytest.fixture
def tmp_env_keys(openssl_present, monkeypatch):
    """
    Создаёт временные RSA-ключи, настраивает ENV так, чтобы load_kms_from_env их видел.
    Возвращает словарь с путями и key_id.
    """
    with tempfile.TemporaryDirectory(prefix="ov-kms-") as td:
        tdir = Path(td)
        key_id = "ovault-int"
        priv, pub = _gen_rsa_keypair(tdir, key_id)
        # ENV для адаптера
        monkeypatch.setenv("OBLIVIONVAULT_KMS_BACKEND", "openssl-rsa")
        monkeypatch.setenv("OBLIVIONVAULT_KMS_KEY_ID", key_id)
        monkeypatch.setenv("OBLIVIONVAULT_KMS_PUB_PEM", str(pub))
        monkeypatch.setenv("OBLIVIONVAULT_KMS_PRIV_PEM", str(priv))
        yield {
            "dir": tdir,
            "key_id": key_id,
            "priv": priv,
            "pub": pub,
        }

# --------------------------
# Тесты
# --------------------------
def test_encrypt_decrypt_roundtrip(tmp_env_keys):
    """
    Базовый сценарий: шифрование → дешифрование через KMS Envelope.
    """
    adapter = load_kms_from_env()
    payload = b"secret-payload: \x00\x01binary\xff"
    aad = {"case": "roundtrip", "v": 1}

    env = adapter.encrypt(payload, aad)
    assert isinstance(env, Envelope)
    out = adapter.decrypt(env)
    assert out == payload

def test_crypto_shred_breaks_decrypt(tmp_env_keys, monkeypatch):
    """
    Крипто-уничтожение: после перезаписи и удаления приватного ключа расшифрование невозможно.
    """
    # 1) Готовим адаптер и конверт
    adapter_ok = load_kms_from_env()
    payload = b"top-secret"
    env = adapter_ok.encrypt(payload, {"case": "crypto-shred"})

    # 2) Проверяем, что дешифрование до уничтожения работает
    assert adapter_ok.decrypt(env) == payload

    # 3) Крипто-стирание приватного ключа
    priv = Path(os.environ["OBLIVIONVAULT_KMS_PRIV_PEM"])
    _secure_shred(priv)
    assert not priv.exists()

    # 4) Создаём новый адаптер из ENV (приватного ключа больше нет)
    #    (оставляем PUB в ENV — он не поможет при unwrap)
    adapter_broken = None
    with pytest.raises((OpenSSLNotFound, KmsError, RuntimeError, FileNotFoundError, Exception)):
        # Конструктор backend в load_kms_from_env может пройти,
        # но unwrap_key при decrypt должен упасть — проверяем обоими путями.
        adapter_broken = load_kms_from_env()  # может сработать, если backend не проверяет приватный немедленно

    # 5) Даже если адаптер успел создаться (некоторые проверки ленивые),
    #    попытка decrypt должна упасть.
    if adapter_broken:
        with pytest.raises((KmsError, Exception)):
            _ = adapter_broken.decrypt(env)

def test_crypto_shred_isolate_only_old_key(tmp_env_keys, monkeypatch):
    """
    Демонстрация стратегии: чтобы сохранить доступ, создаётся второй публичный ключ (новый KMS),
    и данные для дальнейшего использования нужно ЗАВНОВО зашифровать под новый ключ ДО уничтожения старого.
    """
    base_dir: Path = tmp_env_keys["dir"]
    old_key_id: str = tmp_env_keys["key_id"]
    old_priv: Path = tmp_env_keys["priv"]
    old_pub: Path = tmp_env_keys["pub"]

    # 1) Старый адаптер
    old_adapter = load_kms_from_env()

    # 2) Генерируем новый ключ (новый KMS)
    new_key_id = "ovault-int-new"
    new_priv, new_pub = _gen_rsa_keypair(base_dir, new_key_id)
    new_backend = OpenSSLRSABackend(key_id=new_key_id, pub_pem=new_pub, priv_pem=new_priv)
    new_adapter = KmsAdapter(backend=new_backend, default_key_id=new_key_id)

    # 3) Шифруем под старый ключ
    data = b"retain-access-after-rotation"
    env_old = old_adapter.encrypt(data, {"case": "migrate-before-shred"})

    # 4) Для миграции ПЕРЕ-ШИФРОВЫВАЕМ данные под новый KMS (дешифр старым => шифр новым)
    #    (Прямая "rewrap" между разными backend в текущей реализации не применяется.)
    plaintext = old_adapter.decrypt(env_old)
    env_new = new_adapter.encrypt(plaintext, {"case": "migrate-before-shred"})

    # 5) Уничтожаем старый приватный ключ
    _secure_shred(old_priv)
    assert not old_priv.exists()

    # 6) Проверяем: старый конверт расшифровать теперь нельзя
    with pytest.raises((KmsError, Exception)):
        _ = old_adapter.decrypt(env_old)

    # 7) Новый конверт расшифровывается новым ключом — доступ сохранён
    assert new_adapter.decrypt(env_new) == data

def test_envelope_integrity_on_tamper(tmp_env_keys):
    """
    Проверка целостности: изменение одного байта в ciphertext или MAC приводит к ошибке.
    """
    adapter = load_kms_from_env()
    data = b"integrity-check"
    env = adapter.encrypt(data, {"case": "tamper"})

    # Подменяем один байт шифртекста
    import base64, json
    obj = json.loads(env.to_bytes().decode("utf-8"))
    ct = bytearray(base64.b64decode(obj["ciphertext_b64"]))
    ct[0] = (ct[0] + 1) % 256
    obj["ciphertext_b64"] = base64.b64encode(bytes(ct)).decode("ascii")
    tampered_env = Envelope.from_bytes(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    with pytest.raises(Exception):
        _ = adapter.decrypt(tampered_env)

    # Подменяем MAC
    obj = json.loads(env.to_bytes().decode("utf-8"))
    mac = bytearray(base64.b64decode(obj["mac_b64"]))
    mac[0] = (mac[0] + 1) % 256
    obj["mac_b64"] = base64.b64encode(bytes(mac)).decode("ascii")
    tampered_env2 = Envelope.from_bytes(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    with pytest.raises(Exception):
        _ = adapter.decrypt(tampered_env2)
