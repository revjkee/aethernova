import logging
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.detectors.signature_engine import SignatureEngine
from blackvault_core.utils.windows.eventlog_parser import parse_kerberos_events
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("KerberosTGTWatcher")

TGT_EVENT_ID = 4768
DEFAULT_THRESHOLD = 5        # кол-во выдач TGT за X минут
WINDOW_MINUTES = 3           # временной интервал окна
APT_SLEEP_THRESHOLD = 1800   # редкие TGT с высоким риском

class KerberosTGTWatcher:
    def __init__(self, emitter: TelemetryEmitter, engine: SignatureEngine):
        self.emitter = emitter
        self.engine = engine
        self.tgt_cache: Dict[str, list] = {}
        LOG.info("KerberosTGTWatcher initialized")

    def poll(self):
        events = parse_kerberos_events(event_id=TGT_EVENT_ID)
        for evt in events:
            try:
                parsed = self._process_event(evt)
                if parsed:
                    self.emitter.emit(parsed)
                    trace_event("kerberos_tgt_event", parsed)
            except Exception as e:
                LOG.warning(f"TGT parse error: {e}")

    def _process_event(self, evt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        user = evt.get("TargetUserName")
        ip = evt.get("IpAddress")
        timestamp = datetime.utcnow()
        now_ts = timestamp.isoformat()

        if not user or not ip:
            return None

        # Временное окно
        self._cleanup_old(user, timestamp)
        self.tgt_cache.setdefault(user, []).append(timestamp)

        count_recent = len(self.tgt_cache[user])
        risk_score = 0
        tags = []

        if count_recent >= DEFAULT_THRESHOLD:
            tags.append("burst_tgt_issue")
            risk_score += 20

        if self._detect_apt_sleep_cycle(user):
            tags.append("sta_cycle_detected")
            risk_score += 35

        if self.engine.match_signature("kerberos_anomaly", evt):
            tags.append("sig:kerberos_anomaly")
            risk_score += 30

        return {
            "timestamp": now_ts,
            "actor": user,
            "ip_address": ip,
            "event_type": "kerberos_tgt",
            "risk_score": risk_score,
            "event_tags": tags,
            "message": f"TGT issued for {user} from {ip}",
            "classification": self._classify(risk_score)
        }

    def _cleanup_old(self, user: str, now: datetime):
        if user not in self.tgt_cache:
            return
        self.tgt_cache[user] = [
            t for t in self.tgt_cache[user] if now - t < timedelta(minutes=WINDOW_MINUTES)
        ]

    def _detect_apt_sleep_cycle(self, user: str) -> bool:
        if user not in self.tgt_cache:
            return False
        if len(self.tgt_cache[user]) < 2:
            return False
        deltas = [
            (self.tgt_cache[user][i] - self.tgt_cache[user][i - 1]).total_seconds()
            for i in range(1, len(self.tgt_cache[user]))
        ]
        return any(d > APT_SLEEP_THRESHOLD for d in deltas)

    def _classify(self, score: int) -> str:
        if score >= 40:
            return "critical"
        elif score >= 20:
            return "suspicious"
        return "normal"
