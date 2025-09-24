import hashlib
import logging
import subprocess
from typing import Optional, Dict

from blackvault_core.utils.crypto import verify_signature
from blackvault_core.security.alerts import raise_alert
from blackvault_core.zerotrust.image_policy import enforce_image_policy
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.utils.validators import validate_event_schema
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("ImageSignatureVerifier")


class ImageSignatureVerifier:
    def __init__(self, emitter: Optional[TelemetryEmitter] = None):
        self.emitter = emitter or TelemetryEmitter()

    def verify_image(self, image_name: str) -> bool:
        try:
            LOG.info(f"Starting verification for image: {image_name}")

            image_digest = self._get_image_digest(image_name)
            signature = self._fetch_signature(image_name)
            public_key = self._fetch_public_key(image_name)

            if not all([image_digest, signature, public_key]):
                raise ValueError("Missing digest, signature or public key")

            if not verify_signature(image_digest.encode(), signature, public_key):
                raise_alert("invalid_signature", {
                    "image": image_name,
                    "digest": image_digest
                })
                return False

            policy_result = enforce_image_policy(image_name, image_digest)
            if not policy_result:
                raise_alert("policy_violation", {
                    "image": image_name,
                    "digest": image_digest
                })
                return False

            event_record = {
                "event": "image_verified",
                "image": image_name,
                "digest": image_digest,
                "source": "image_signature_verifier",
            }

            validate_event_schema("image_verification", event_record)
            self.emitter.emit(event_record)
            trace_event("image_integrity_check", event_record)

            LOG.info(f"Image verified: {image_name}")
            return True
        except Exception as e:
            LOG.error(f"Image verification failed for {image_name}: {e}")
            raise_alert("image_verification_error", {"image": image_name, "error": str(e)})
            return False

    def _get_image_digest(self, image_name: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format='{{index .RepoDigests 0}}'", image_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
            digest_line = result.stdout.strip().strip("'")
            return digest_line.split("@")[1] if "@" in digest_line else None
        except Exception as e:
            LOG.warning(f"Failed to get digest for {image_name}: {e}")
            return None

    def _fetch_signature(self, image_name: str) -> Optional[bytes]:
        # PLACEHOLDER: fetch from trusted source, OCI registry or secure vault
        try:
            with open(f"/var/blackvault/signatures/{image_name}.sig", "rb") as f:
                return f.read()
        except Exception as e:
            LOG.warning(f"Signature missing for {image_name}: {e}")
            return None

    def _fetch_public_key(self, image_name: str) -> Optional[bytes]:
        # PLACEHOLDER: per-image trust anchor resolution
        try:
            with open("/etc/blackvault/trusted_pubkey.pem", "rb") as f:
                return f.read()
        except Exception as e:
            LOG.warning(f"Public key unavailable for {image_name}: {e}")
            return None
