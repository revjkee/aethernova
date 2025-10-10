import os
import psutil
import time
import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List

from .signal_hooks import TraceCollector
from .ml_profile_checker import BehaviorClassifier
from .rule_engine import SignatureRuleEngine

logger = logging.getLogger("telemetry.behavior_sensor")
logger.setLevel(logging.INFO)


class BehaviorSensor:
    def __init__(self, scan_interval: float = 1.0):
        self.scan_interval = scan_interval
        self.rule_engine = SignatureRuleEngine()
        self.ml_classifier = BehaviorClassifier()
        self.tracer = TraceCollector()
        self.previous_pids = set()
        self.hostname = os.uname()[1]

    async def start(self):
        logger.info("BehaviorSensor started.")
        while True:
            try:
                await self._scan_and_analyze()
                await asyncio.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Behavior sensor error: {e}")

    async def _scan_and_analyze(self):
        current_pids = set(psutil.pids())
        new_pids = current_pids - self.previous_pids
        terminated_pids = self.previous_pids - current_pids
        self.previous_pids = current_pids

        for pid in new_pids:
            await self._handle_new_process(pid)

        for pid in current_pids:
            await self._analyze_process(pid)

    async def _handle_new_process(self, pid: int):
        try:
            proc = psutil.Process(pid)
            metadata = {
                "pid": pid,
                "ppid": proc.ppid(),
                "cmdline": proc.cmdline(),
                "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
                "user": proc.username(),
                "exe": proc.exe() if proc.exe() else "",
                "cwd": proc.cwd() if proc.cwd() else "",
            }
            logger.debug(f"New process detected: {metadata}")
            self.tracer.attach(pid)
        except Exception as e:
            logger.warning(f"Failed to attach tracer to pid={pid}: {e}")

    async def _analyze_process(self, pid: int):
        try:
            trace_data = self.tracer.get_trace(pid)
            if not trace_data:
                return

            feature_vector = self._extract_features(trace_data)
            rule_result = self.rule_engine.evaluate(feature_vector)
            ml_result = self.ml_classifier.classify(feature_vector)

            if rule_result["malicious"] or ml_result["suspicious"]:
                alert = self._build_alert(pid, feature_vector, rule_result, ml_result)
                await self._report_alert(alert)
        except Exception as e:
            logger.debug(f"Analysis error on PID {pid}: {e}")

    def _extract_features(self, trace: List[Dict[str, Any]]) -> Dict[str, Any]:
        feature_vector = {
            "syscall_sequence": [entry["name"] for entry in trace],
            "frequency_map": {},
            "entropy": 0,
        }
        freq = {}
        for entry in trace:
            freq[entry["name"]] = freq.get(entry["name"], 0) + 1
        feature_vector["frequency_map"] = freq
        feature_vector["entropy"] = self._calculate_entropy(freq)
        return feature_vector

    def _calculate_entropy(self, freq_map: Dict[str, int]) -> float:
        import math
        total = sum(freq_map.values())
        return -sum((count/total) * math.log2(count/total) for count in freq_map.values() if count)

    def _build_alert(self, pid: int, features: Dict[str, Any], rule: Dict, ml: Dict) -> Dict[str, Any]:
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "pid": pid,
            "host": self.hostname,
            "feature_summary": features,
            "rule_triggered": rule,
            "ml_inference": ml,
            "alert_type": "process_behavior_anomaly",
        }

    async def _report_alert(self, alert: Dict[str, Any]):
        logger.warning(f"[ALERT] {json.dumps(alert)}")
        # Optional: send to SIEM or async queue


async def main():
    sensor = BehaviorSensor()
    await sensor.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Behavior sensor shutdown.")
