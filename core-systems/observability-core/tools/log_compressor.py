# observability/dashboards/tools/log_compressor.py

import hashlib
import json
from typing import Any, Dict, List, Optional


class LogCompressor:
    """
    Модуль для интеллектуальной компрессии логов:
    - удаляет повторяющиеся сообщения (дедупликация);
    - агрегирует события по шаблону (fingerprint);
    - очищает от мусорных или чувствительных полей;
    - применяет свёртку частотных записей в агрегаты.
    """

    def __init__(self, keep_fields: Optional[List[str]] = None, fingerprint_fields: Optional[List[str]] = None):
        self.keep_fields = keep_fields or ["timestamp", "level", "message"]
        self.fingerprint_fields = fingerprint_fields or ["message", "source", "code"]
        self._cache = {}

    def _hash_fingerprint(self, log: Dict[str, Any]) -> str:
        base = {k: log.get(k, "") for k in self.fingerprint_fields}
        data = json.dumps(base, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def _sanitize(self, log: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in log.items() if k in self.keep_fields}

    def compress_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        compressed = []
        for log in logs:
            log_clean = self._sanitize(log)
            fingerprint = self._hash_fingerprint(log_clean)

            if fingerprint not in self._cache:
                self._cache[fingerprint] = {**log_clean, "count": 1}
            else:
                self._cache[fingerprint]["count"] += 1

        for entry in self._cache.values():
            compressed.append(entry)

        return compressed

    def reset_cache(self):
        self._cache.clear()
