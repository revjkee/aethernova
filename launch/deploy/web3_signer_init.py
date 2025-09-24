import json
import os
import time
from web3 import Web3
from eth_account import Account
from hashlib import sha256
from pathlib import Path

CONFIG_PATH = os.getenv("WEB3_SIGNER_CONFIG", "secrets/web3_signer.json")
LAUNCH_HASH_PATH = "approvals/launch_signatures/launch.sig"

def load_config(path):
    with open(path, "r") as f:
        return json.load(f)

def generate_launch_hash(metadata: dict) -> str:
    joined = json.dumps(metadata, sort_keys=True).encode("utf-8")
    return sha256(joined).hexdigest()

def sign_hash(hash_str, private_key):
    acct = Account.from_key(private_key)
    signed = acct.signHash(hexstr=hash_str)
    return signed.signature.hex(), acct.address

def persist_signature(hash_str, signature, address):
    Path(os.path.dirname(LAUNCH_HASH_PATH)).mkdir(parents=True, exist_ok=True)
    with open(LAUNCH_HASH_PATH, "w") as f:
        json.dump({
            "launch_hash": hash_str,
            "signature": signature,
            "signer": address,
            "timestamp": int(time.time())
        }, f, indent=2)

def main():
    config = load_config(CONFIG_PATH)

    private_key = config.get("private_key")
    network_rpc = config.get("rpc_url", "https://mainnet.infura.io/v3/YOUR_PROJECT_ID")
    w3 = Web3(Web3.HTTPProvider(network_rpc))

    metadata = {
        "ai_core_version": os.getenv("AI_CORE_VERSION", "unknown"),
        "bot_version": os.getenv("BOT_VERSION", "unknown"),
        "commit_hash": os.getenv("GIT_COMMIT_HASH", "undefined"),
        "env": os.getenv("ENVIRONMENT", "development"),
        "genesis_mode": os.getenv("GENESIS_MODE", "false") == "true",
        "timestamp": int(time.time())
    }

    launch_hash = generate_launch_hash(metadata)
    signature, address = sign_hash(launch_hash, private_key)

    persist_signature(launch_hash, signature, address)
    print(f"[web3 signer] Launch signed by: {address}")
    print(f"[web3 signer] Launch hash: {launch_hash}")
    print(f"[web3 signer] Signature: {signature}")

if __name__ == "__main__":
    main()
