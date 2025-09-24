import pytest
import time
from plugins.utils.plugin_signature import sign_data, verify_signature, SignatureError

PRIVATE_KEY = "super_secure_dev_key"
INVALID_KEY = "hacker_key"
PLUGIN_PAYLOAD = b"example_plugin_payload"

def test_valid_signature():
    sig = sign_data(PLUGIN_PAYLOAD, PRIVATE_KEY)
    assert verify_signature(PLUGIN_PAYLOAD, sig, PRIVATE_KEY)

def test_invalid_signature_wrong_key():
    sig = sign_data(PLUGIN_PAYLOAD, INVALID_KEY)
    assert not verify_signature(PLUGIN_PAYLOAD, sig, PRIVATE_KEY)

def test_signature_modified_payload():
    sig = sign_data(PLUGIN_PAYLOAD, PRIVATE_KEY)
    altered_payload = b"tampered_payload"
    assert not verify_signature(altered_payload, sig, PRIVATE_KEY)

def test_signature_with_empty_payload():
    sig = sign_data(b"", PRIVATE_KEY)
    assert verify_signature(b"", sig, PRIVATE_KEY)

def test_signature_with_unicode_payload():
    data = "плагин:🚀v1.0".encode("utf-8")
    sig = sign_data(data, PRIVATE_KEY)
    assert verify_signature(data, sig, PRIVATE_KEY)

def test_signature_with_large_payload():
    data = b"x" * 10_000_000  # 10 MB
    sig = sign_data(data, PRIVATE_KEY)
    assert verify_signature(data, sig, PRIVATE_KEY)

def test_signature_reuse_detection():
    data = b"critical_logic"
    sig = sign_data(data, PRIVATE_KEY)
    assert verify_signature(data, sig, PRIVATE_KEY)
    assert not verify_signature(data + b"_extra", sig, PRIVATE_KEY)

def test_signature_tampering_attempt():
    sig = sign_data(PLUGIN_PAYLOAD, PRIVATE_KEY)
    corrupted_sig = sig[:-1] + ("Z" if sig[-1] != "Z" else "X")
    assert not verify_signature(PLUGIN_PAYLOAD, corrupted_sig, PRIVATE_KEY)

def test_signature_expiry():
    from plugins.utils.plugin_signature import sign_data_with_expiry, verify_signature_with_expiry

    data = b"expires_in_1s"
    sig = sign_data_with_expiry(data, PRIVATE_KEY, ttl_seconds=1)
    assert verify_signature_with_expiry(data, sig, PRIVATE_KEY)
    time.sleep(2)
    assert not verify_signature_with_expiry(data, sig, PRIVATE_KEY)

def test_signature_versioning_support():
    from plugins.utils.plugin_signature import sign_data_with_version, verify_signature_with_version

    version = "1.0.3"
    sig = sign_data_with_version(PLUGIN_PAYLOAD, PRIVATE_KEY, version=version)
    assert verify_signature_with_version(PLUGIN_PAYLOAD, sig, PRIVATE_KEY, expected_version=version)

def test_signature_version_mismatch():
    from plugins.utils.plugin_signature import sign_data_with_version, verify_signature_with_version

    sig = sign_data_with_version(PLUGIN_PAYLOAD, PRIVATE_KEY, version="2.1.0")
    assert not verify_signature_with_version(PLUGIN_PAYLOAD, sig, PRIVATE_KEY, expected_version="1.0.0")

def test_error_on_signature_malformed():
    with pytest.raises(SignatureError):
        verify_signature(PLUGIN_PAYLOAD, "this_is_not_valid_signature", PRIVATE_KEY)
