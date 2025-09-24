import time
import logging
from datetime import datetime
from collections import defaultdict

from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.utils.netflow import NetflowCollector, Flow
from blackvault_core.ml.beacon_detector import BeaconDetector
from blackvault_core.ml.flow_classifier import FlowClassifier
from blackvault_core.security.alerts import raise_alert
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("NetFlowAnalyzer")

class NetFlowAnalyzer:
    def __init__(self, emitter: TelemetryEmitter, listen_port: int = 2055):
        self.collector = NetflowCollector(port=listen_port)
        self.emitter = emitter
        self.beacon_detector = BeaconDetector()
        self.flow_classifier = FlowClassifier()
        self.session_window = defaultdict(list)
        LOG.info("NetFlowAnalyzer initialized on port %d", listen_port)

    def run(self):
        LOG.info("Starting NetFlow analysis loop...")
        for flow in self.collector.listen():
            try:
                self._process_flow(flow)
            except Exception as e:
                LOG.exception("Error processing flow: %s", e)

    def _process_flow(self, flow: Flow):
        src_dst_pair = (flow.src_ip, flow.dst_ip)
        self.session_window[src_dst_pair].append(flow)

        if self._should_analyze(src_dst_pair):
            flows = self.session_window.pop(src_dst_pair)
            self._analyze_session(flows)

    def _should_analyze(self, key):
        return len(self.session_window[key]) >= 10

    def _analyze_session(self, flows: list):
        beaconing_score = self.beacon_detector.analyze(flows)
        category = self.flow_classifier.classify(flows)

        if beaconing_score > 0.85 or category == "C2":
            alert_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "src_ip": flows[0].src_ip,
                "dst_ip": flows[0].dst_ip,
                "category": category,
                "beaconing_score": beaconing_score,
                "flow_count": len(flows),
                "detected_by": "NetFlowAnalyzer"
            }
            LOG.warning("Suspicious NetFlow detected: %s", alert_data)
            self.emitter.emit({
                "event": "suspicious_netflow",
                "details": alert_data
            })
            raise_alert("netflow_c2_detected", alert_data)
            trace_event("netflow_beacon_pattern", alert_data)
