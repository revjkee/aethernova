import logging
import json
import hashlib
from typing import Dict, Any, List
from datetime import datetime

from genesisops_core.security.signature import verify_digital_signature
from genesisops_core.ai.policy_check import validate_model_policy
from genesisops_core.ai.risk_analyzer import assess_behavioral_risk
from genesisops_core.control.audit import log_release_validation_event
from genesisops_core.core.errors import ReleaseValidationError

logger = logging.getLogger("version.ai_release_validator")
logging.basicConfig(level=logging.INFO)

REQUIRED_FIELDS = ["release_id", "model_name", "version", "checksum", "signature", "policies"]
MIN_ACCEPTABLE_CONFIDENCE = 0.87
MAX_ALLOWED_RISK_SCORE = 0.15

class AIReleaseValidator:
    def __init__(self):
        pass

    def _validate_structure(self, release: Dict[str, Any]):
        missing = [f for f in REQUIRED_FIELDS if f not in release]
        if missing:
            raise ReleaseValidationError(f"Missing fields: {', '.join(missing)}")

    def _verify_integrity(self, release: Dict[str, Any]) -> bool:
        data = json.dumps({
            "release_id": release["release_id"],
            "model_name": release["model_name"],
            "version": release["version"],
            "checksum": release["checksum"]
        }, sort_keys=True).encode()

        signature = release.get("signature")
        verified = verify_digital_signature(data, signature)
        if not verified:
            raise ReleaseValidationError("Signature verification failed")
        return True

    def _validate_checksum(self, file_path: str, expected_checksum: str) -> bool:
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            if file_hash != expected_checksum:
                raise ReleaseValidationError("Checksum mismatch")
            return True
        except Exception as e:
            raise ReleaseValidationError(f"Checksum validation failed: {e}")

    def _run_policy_validation(self, release: Dict[str, Any]) -> bool:
        results = validate_model_policy(release["model_name"], release["policies"])
        if not results["approved"]:
            raise ReleaseValidationError(f"Policy check failed: {results['reason']}")
        return True

    def _run_risk_assessment(self, model_path: str) -> bool:
        risk_score, confidence = assess_behavioral_risk(model_path)
        if risk_score > MAX_ALLOWED_RISK_SCORE:
            raise ReleaseValidationError(f"Risk score too high: {risk_score}")
        if confidence < MIN_ACCEPTABLE_CONFIDENCE:
            raise ReleaseValidationError(f"Confidence too low: {confidence}")
        return True

    def validate_release(self, release: Dict[str, Any], model_file_path: str) -> Dict[str, Any]:
        try:
            self._validate_structure(release)
            self._verify_integrity(release)
            self._validate_checksum(model_file_path, release["checksum"])
            self._run_policy_validation(release)
            self._run_risk_assessment(model_file_path)

            audit_log = {
                "release_id": release["release_id"],
                "model": release["model_name"],
                "version": release["version"],
                "timestamp": datetime.utcnow().isoformat(),
                "status": "validated"
            }
            log_release_validation_event(audit_log)
            logger.info(f"Release {release['release_id']} successfully validated")
            return audit_log

        except ReleaseValidationError as e:
            logger.error(f"Release validation failed: {e}")
            raise

        except Exception as e:
            logger.exception("Unexpected error during release validation")
            raise ReleaseValidationError("Fatal validation error") from e
