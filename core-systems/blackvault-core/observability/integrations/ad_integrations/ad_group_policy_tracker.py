import logging
import json
import time
from typing import Dict, Any, Optional
from datetime import datetime

import win32com.client
import pythoncom

from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.detectors.signature_engine import SignatureEngine
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("ADGroupPolicyTracker")

class ADGroupPolicyTracker:
    def __init__(self, emitter: TelemetryEmitter, engine: SignatureEngine):
        self.emitter = emitter
        self.engine = engine
        self.gpo_state: Dict[str, Dict[str, Any]] = {}
        LOG.info("ADGroupPolicyTracker initialized")

    def poll(self):
        pythoncom.CoInitialize()
        gpm = win32com.client.Dispatch("GPMgmt.GPM")
        domain = gpm.GetDomain(".", "", 0)
        gpo_collection = domain.SearchGPOs()

        for i in range(gpo_collection.Count):
            gpo = gpo_collection.Item(i)
            gpo_info = self._extract_gpo_info(gpo)

            gpo_id = gpo_info["id"]
            previous = self.gpo_state.get(gpo_id)

            if previous:
                delta = self._detect_change(previous, gpo_info)
                if delta:
                    self._emit_change(gpo_info, delta)
            else:
                trace_event("ad_gpo_detected", gpo_info)

            self.gpo_state[gpo_id] = gpo_info

        pythoncom.CoUninitialize()

    def _extract_gpo_info(self, gpo) -> Dict[str, Any]:
        return {
            "id": gpo.ID,
            "name": gpo.DisplayName,
            "owner": gpo.Owner,
            "version": gpo.VersionNumber,
            "creation": str(gpo.CreationTime),
            "modification": str(gpo.ModificationTime),
            "status": str(gpo.GPOStatus),
            "enabled": gpo.GpoEnabled,
            "links": [str(link.Path) for link in gpo.GetGPOLinks()],
        }

    def _detect_change(self, old: Dict[str, Any], new: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        delta = {}
        for key in new:
            if old.get(key) != new.get(key):
                delta[key] = {"old": old.get(key), "new": new.get(key)}
        return delta if delta else None

    def _emit_change(self, gpo_info: Dict[str, Any], delta: Dict[str, Any]):
        score = self._calculate_risk(delta)
        classification = self._classify(score)

        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "gpo_id": gpo_info["id"],
            "gpo_name": gpo_info["name"],
            "changed_by": gpo_info.get("owner"),
            "event_type": "gpo_change",
            "delta": delta,
            "risk_score": score,
            "classification": classification,
            "message": f"GPO '{gpo_info['name']}' was modified",
        }

        self.emitter.emit(payload)
        trace_event("ad_gpo_change", payload)

    def _calculate_risk(self, delta: Dict[str, Any]) -> int:
        score = 0
        for key in delta:
            if key in ["owner", "enabled"]:
                score += 20
            elif key in ["links", "version"]:
                score += 10
            elif key == "modification":
                score += 5

        if self.engine.match_signature("gpo_persistence", delta):
            score += 40

        return score

    def _classify(self, score: int) -> str:
        if score >= 50:
            return "critical"
        elif score >= 25:
            return "suspicious"
        return "informational"
