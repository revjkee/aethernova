import logging
import json
from typing import List, Dict, Optional
from hr_ai.db.models import Candidate, JobPosting
from hr_ai.security.secrets_manager import SecretsManager
from hr_ai.utils.retry import retry_with_backoff
from hr_ai.utils.encryption import encrypt_payload
from hr_ai.utils.telemetry import log_export_event
import requests

logger = logging.getLogger("export_to_hris")
logger.setLevel(logging.INFO)


class HRISExporter:
    def __init__(self, system_name: str = "workday"):
        self.system_name = system_name.lower()
        self.secrets = SecretsManager()
        self.api_key = self.secrets.get_secret(f"{self.system_name.upper()}_API_KEY")
        self.api_url = self._resolve_api_url()

    def _resolve_api_url(self) -> str:
        endpoints = {
            "workday": "https://api.workday.com/v1/hr/data",
            "bamboohr": "https://api.bamboohr.com/api/gateway.php/company/v1/employees",
            "sap": "https://api.successfactors.com/hris/v2/entities"
        }
        if self.system_name not in endpoints:
            raise ValueError(f"Unsupported HRIS system: {self.system_name}")
        return endpoints[self.system_name]

    def _build_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def _format_candidate(self, candidate: Candidate) -> Dict:
        return {
            "full_name": candidate.full_name,
            "email": candidate.email,
            "phone": candidate.phone,
            "position_applied": candidate.position,
            "skills": candidate.skills,
            "source": candidate.source,
            "experience_years": candidate.experience_years
        }

    def _format_job_posting(self, job: JobPosting) -> Dict:
        return {
            "job_id": job.id,
            "title": job.title,
            "department": job.department,
            "location": job.location,
            "requirements": job.requirements,
            "salary_range": job.salary_range,
            "status": job.status
        }

    @retry_with_backoff(retries=3, delay=2)
    def export_candidates(self, candidates: List[Candidate]) -> bool:
        payload = [self._format_candidate(c) for c in candidates]
        return self._send_payload(payload, object_type="candidate")

    @retry_with_backoff(retries=3, delay=2)
    def export_job_postings(self, postings: List[JobPosting]) -> bool:
        payload = [self._format_job_posting(p) for p in postings]
        return self._send_payload(payload, object_type="job_posting")

    def _send_payload(self, data: List[Dict], object_type: str) -> bool:
        if not data:
            logger.warning(f"No {object_type}s to export.")
            return False

        encrypted_data = encrypt_payload(data)
        headers = self._build_headers()

        try:
            response = requests.post(
                self.api_url,
                headers=headers,
                data=json.dumps(encrypted_data),
                timeout=15
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"[{self.system_name}] Failed to export {object_type}s: {e}")
            return False

        logger.info(f"[{self.system_name}] Successfully exported {len(data)} {object_type}s.")
        log_export_event(system=self.system_name, object_type=object_type, count=len(data))
        return True
