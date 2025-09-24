#!/usr/bin/env python3

import os
import json
import hashlib
import logging
from pathlib import Path

VERSION_MANIFEST = Path("launch/versioning/version_manifest.yaml")
UPGRADE_NOTICE = Path("launch/versioning/upgrade_notices.md")
STATE_LOG = Path("launch/self_state/ai_state_log.json")
DIAGNOSTIC_LOG = Path("launch/diagnostics/error_dump.log")

logging.basicConfig(filename=DIAGNOSTIC_LOG, level=logging.INFO)

def parse_version_manifest():
    import yaml
    if not VERSION_MANIFEST.exists():
        logging.error(f"[VERSION] Manifest missing: {VERSION_MANIFEST}")
        return None
    with open(VERSION_MANIFEST, "r") as f:
        return yaml.safe_load(f)

def calculate_hash(path: Path) -> str:
    if not path.exists():
        return None
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def validate_versions(manifest):
    mismatches = []
    for component in manifest.get("components", []):
        file_path = Path(component.get("path"))
        expected_hash = component.get("sha256")
        actual_hash = calculate_hash(file_path)

        if actual_hash is None:
            logging.warning(f"[VERSION] MISSING: {file_path}")
            mismatches.append((file_path, "MISSING"))
        elif actual_hash != expected_hash:
            logging.error(f"[VERSION] HASH MISMATCH: {file_path}")
            mismatches.append((file_path, "HASH_MISMATCH"))
        else:
            logging.info(f"[VERSION] OK: {file_path}")
    return mismatches

def check_upgrade_notices():
    if not UPGRADE_NOTICE.exists():
        logging.warning(f"[NOTICE] No upgrade notices found at {UPGRADE_NOTICE}")
        return
    with open(UPGRADE_NOTICE, "r") as f:
        notices = f.read()
    logging.info(f"[NOTICE] Upgrade summary found: {len(notices.splitlines())} lines")

def write_sync_result(mismatches):
    sync_state = {
        "version_sync_ok": len(mismatches) == 0,
        "mismatched_files": [str(f[0]) for f in mismatches],
        "total_checked": len(mismatches)
    }
    STATE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_LOG, "w") as f:
        json.dump(sync_state, f, indent=2)

def run_sync_checker():
    logging.info("=== VERSION SYNC CHECK INITIATED ===")
    manifest = parse_version_manifest()
    if not manifest:
        return
    mismatches = validate_versions(manifest)
    check_upgrade_notices()
    write_sync_result(mismatches)
    logging.info("=== VERSION SYNC COMPLETE ===")

if __name__ == "__main__":
    run_sync_checker()
