import json
import os
import time
from eth_account import Account
from eth_account.messages import encode_defunct
from pathlib import Path
from hashlib import sha256

LAUNCH_SIG_PATH = "approvals/launch_signatures/launch.sig"
PUBLIC_KEYS_DIR = "approvals/launch_signatures/"
REQUIRED_SIGNERS = [
    "launch.pub"
]

def read_signature_file(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"[verifier] Signature file not found: {path}")
    with open(path, "r") as f:
        return json.load(f)

def verify_signature(launch_hash, signature_hex, expected_address):
    message = encode_defunct(hexstr=launch_hash)
    recovered = Account.recover_message(message, signature=signature_hex)
    return recovered.lower() == expected_address.lower()

def load_pubkey_address(pubkey_path):
    with open(pubkey_path, "r") as f:
        key = f.read().strip()
    return Account.from_key(key).address

def main():
    print("[verifier] Verifying launch signature...")

    sig_data = read_signature_file(LAUNCH_SIG_PATH)
    launch_hash = sig_data["launch_hash"]
    signature = sig_data["signature"]
    signer = sig_data["signer"]

    for pub in REQUIRED_SIGNERS:
        pubkey_path = os.path.join(PUBLIC_KEYS_DIR, pub)
        try:
            expected_address = load_pubkey_address(pubkey_path)
        except Exception:
            print(f"[verifier] Failed to read pubkey from {pubkey_path}")
            continue

        is_valid = verify_signature(launch_hash, signature, expected_address)
        if is_valid:
            print(f"[verifier] Signature valid. Signed by authorized key: {expected_address}")
            return

    print("[verifier] ERROR: Signature verification failed. Launch unauthorized.")
    raise SystemExit(1)

if __name__ == "__main__":
    main()
