import requests
import logging
from typing import Dict, Optional, List
from hr_ai.core.env import get_env_secret
from hr_ai.security.secrets_manager import SecretsManager
from hr_ai.models.job import JobPosting
from hr_ai.utils.retry import retry_with_backoff
from hr_ai.utils.trace import trace_request

logger = logging.getLogger("job_board_api")
logger.setLevel(logging.INFO)


class JobBoardClient:
    def __init__(self, platform: str):
        self.platform = platform.lower()
        self.secrets = SecretsManager()
        self.session = requests.Session()
        self.headers = self._build_headers()

    def _build_headers(self) -> Dict[str, str]:
        token = self.secrets.get_secret(f"{self.platform.upper()}_API_TOKEN")
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "HR-AI-System/1.0"
        }

    @retry_with_backoff(retries=3, delay=2)
    @trace_request
    def post_job(self, job: JobPosting) -> Dict:
        url = self._get_endpoint("post")
        payload = self._map_job_to_payload(job)

        response = self.session.post(url, headers=self.headers, json=payload, timeout=10)
        response.raise_for_status()

        logger.info(f"[{self.platform}] Job posted: {job.external_id}")
        return response.json()

    @retry_with_backoff(retries=3, delay=2)
    @trace_request
    def update_job(self, job: JobPosting) -> Dict:
        url = self._get_endpoint("update", job.external_id)
        payload = self._map_job_to_payload(job)

        response = self.session.put(url, headers=self.headers, json=payload, timeout=10)
        response.raise_for_status()

        logger.info(f"[{self.platform}] Job updated: {job.external_id}")
        return response.json()

    @retry_with_backoff(retries=3, delay=2)
    @trace_request
    def delete_job(self, external_id: str) -> Dict:
        url = self._get_endpoint("delete", external_id)

        response = self.session.delete(url, headers=self.headers, timeout=10)
        response.raise_for_status()

        logger.info(f"[{self.platform}] Job deleted: {external_id}")
        return response.json()

    def _get_endpoint(self, action: str, resource_id: Optional[str] = None) -> str:
        endpoints = {
            "linkedin": {
                "post": "https://api.linkedin.com/v2/jobs",
                "update": f"https://api.linkedin.com/v2/jobs/{resource_id}",
                "delete": f"https://api.linkedin.com/v2/jobs/{resource_id}",
            },
            "headhunter": {
                "post": "https://api.hh.ru/vacancies",
                "update": f"https://api.hh.ru/vacancies/{resource_id}",
                "delete": f"https://api.hh.ru/vacancies/{resource_id}",
            },
            "indeed": {
                "post": "https://employers.indeed.com/api/jobs",
                "update": f"https://employers.indeed.com/api/jobs/{resource_id}",
                "delete": f"https://employers.indeed.com/api/jobs/{resource_id}",
            }
        }

        if self.platform not in endpoints or action not in endpoints[self.platform]:
            raise ValueError(f"Unsupported platform/action: {self.platform}/{action}")

        return endpoints[self.platform][action]

    def _map_job_to_payload(self, job: JobPosting) -> Dict:
        if self.platform == "linkedin":
            return {
                "title": job.title,
                "description": job.description,
                "location": job.location,
                "employmentType": job.employment_type,
                "companyName": job.company,
                "externalJobPostingId": job.external_id,
            }
        elif self.platform == "headhunter":
            return {
                "name": job.title,
                "description": job.description,
                "area": job.location_id,
                "employment": {"id": job.employment_type},
                "employer": {"name": job.company},
                "external_id": job.external_id,
            }
        elif self.platform == "indeed":
            return {
                "job_title": job.title,
                "job_description": job.description,
                "job_location": job.location,
                "job_type": job.employment_type,
                "company_name": job.company,
                "external_id": job.external_id,
            }
        else:
            raise ValueError(f"Unsupported platform: {self.platform}")
