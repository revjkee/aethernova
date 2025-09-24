# interview_scheduler.py
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta

from hr_ai.core.env import get_env_secret
from hr_ai.security.secrets_manager import SecretsManager
from hr_ai.models.interview import InterviewSlot, CandidateProfile
from hr_ai.utils.timezone_utils import convert_to_utc, localize_datetime
from hr_ai.utils.notifications import notify_participants
from hr_ai.utils.retry import retry_with_backoff

import requests

logger = logging.getLogger("interview_scheduler")
logger.setLevel(logging.INFO)


class InterviewScheduler:
    def __init__(self, platform: str = "google"):
        self.platform = platform.lower()
        self.secrets = SecretsManager()
        self.token = self.secrets.get_secret(f"{self.platform.upper()}_CALENDAR_TOKEN")
        self.api_url = self._get_api_url()

    def _get_api_url(self) -> str:
        urls = {
            "google": "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            "outlook": "https://graph.microsoft.com/v1.0/me/events"
        }
        if self.platform not in urls:
            raise ValueError(f"Unsupported platform: {self.platform}")
        return urls[self.platform]

    def _build_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def _build_payload(self, slot: InterviewSlot, candidate: CandidateProfile) -> Dict:
        start_utc = convert_to_utc(slot.start_time)
        end_utc = convert_to_utc(slot.end_time)

        return {
            "summary": f"Interview with {candidate.full_name}",
            "location": "Online",
            "description": f"Position: {slot.position}\nStage: {slot.stage}",
            "start": {"dateTime": start_utc.isoformat(), "timeZone": "UTC"},
            "end": {"dateTime": end_utc.isoformat(), "timeZone": "UTC"},
            "attendees": [{"email": email} for email in slot.participants_emails],
            "reminders": {
                "useDefault": False,
                "overrides": [{"method": "email", "minutes": 30}]
            }
        }

    @retry_with_backoff(retries=3, delay=2)
    def schedule(self, slot: InterviewSlot, candidate: CandidateProfile) -> Optional[str]:
        payload = self._build_payload(slot, candidate)
        headers = self._build_headers()

        response = requests.post(self.api_url, headers=headers, json=payload, timeout=10)
        if response.status_code not in [200, 201]:
            logger.error(f"[{self.platform}] Failed to schedule interview: {response.text}")
            return None

        event_id = response.json().get("id")
        logger.info(f"[{self.platform}] Interview scheduled. Event ID: {event_id}")
        notify_participants(slot.participants_emails + [candidate.email], payload)
        return event_id

    @retry_with_backoff(retries=3, delay=2)
    def cancel(self, event_id: str) -> bool:
        url = f"{self.api_url}/{event_id}"
        headers = self._build_headers()

        response = requests.delete(url, headers=headers, timeout=10)
        if response.status_code != 204:
            logger.error(f"[{self.platform}] Failed to cancel event {event_id}: {response.text}")
            return False

        logger.info(f"[{self.platform}] Event {event_id} successfully cancelled")
        return True
