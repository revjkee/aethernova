# platform-security/genius-core-security/defense/threat_db.py

import threading
import hashlib
import json
import time
from typing import Dict, List, Optional
from datetime import datetime

from genius_core_security.validators.utils.hash_context import hash_context

class ThreatEntry:
    def __init__(self, signature_id: str, ioc: Dict[str, str], severity: str, source: str):
        self.signature_id = signature_id
        self.ioc = ioc  # Пример: {"ip": "1.2.3.4", "domain": "malicious.site"}
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL
        self.source = source  # источник сигнатуры (внутренний/внешний)
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict:
        return {
            "signature_id": self.signature_id,
            "ioc": self.ioc,
            "severity": self.severity,
            "source": self.source,
            "timestamp": self.timestamp
        }

class ThreatDB:
    def __init__(self):
        self._threat_index: Dict[str, ThreatEntry] = {}
        self._lock = threading.Lock()

    def _generate_signature_id(self, ioc: Dict[str, str]) -> str:
        sorted_ioc = json.dumps(ioc, sort_keys=True)
        return hashlib.sha256(sorted_ioc.encode()).hexdigest()

    def add_threat(self, ioc: Dict[str, str], severity: str, source: str) -> str:
        with self._lock:
            sig_id = self._generate_signature_id(ioc)
            if sig_id not in self._threat_index:
                entry = ThreatEntry(sig_id, ioc, severity, source)
                self._threat_index[sig_id] = entry
            return sig_id

    def get_threat_by_ioc(self, ioc: Dict[str, str]) -> Optional[Dict]:
        sig_id = self._generate_signature_id(ioc)
        with self._lock:
            entry = self._threat_index.get(sig_id)
            return entry.to_dict() if entry else None

    def list_all(self) -> List[Dict]:
        with self._lock:
            return [entry.to_dict() for entry in self._threat_index.values()]

    def update_threat(self, sig_id: str, new_ioc: Dict[str, str], severity: Optional[str] = None):
        with self._lock:
            if sig_id in self._threat_index:
                entry = self._threat_index[sig_id]
                entry.ioc = new_ioc
                if severity:
                    entry.severity = severity
                entry.timestamp = datetime.utcnow().isoformat()

    def remove_threat(self, sig_id: str) -> bool:
        with self._lock:
            if sig_id in self._threat_index:
                del self._threat_index[sig_id]
                return True
            return False

    def purge_old_entries(self, max_age_seconds: int = 86400):
        threshold = time.time() - max_age_seconds
        with self._lock:
            for sig_id in list(self._threat_index.keys()):
                ts = self._threat_index[sig_id].timestamp
                if datetime.fromisoformat(ts).timestamp() < threshold:
                    del self._threat_index[sig_id]
