import os
import time
import json
import logging
import threading
from typing import Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from monitoring.logging.audit.audit_parser import AuditParser
from monitoring.logging.tracing.trace_context import trace_with_context
from monitoring.alerting.receivers.telegram_alert import send_telegram_alert  # можно отключать при необходимости
from monitoring.ai_monitors.auto_silencer import auto_silence_event  # AI-модуль
from monitoring.incident_replay.scheduler import schedule_replay  # реплей в случае флага

logger = logging.getLogger("audit_watcher")
logger.setLevel(logging.INFO)

AUDIT_LOG_PATH = "/var/log/teslaai/audit.log"
AUDIT_SOURCE = "local_audit_daemon"

class AuditEventHandler(FileSystemEventHandler):
    def __init__(self, parser: AuditParser):
        self.parser = parser

    def on_modified(self, event):
        if event.src_path == AUDIT_LOG_PATH:
            logger.debug(f"[AUDIT] Detected change in audit log: {event.src_path}")
            self._handle_new_events()

    def _handle_new_events(self):
        try:
            with open(AUDIT_LOG_PATH, "r") as f:
                lines = f.readlines()[-50:]  # Читаем только последние записи
            for raw in lines:
                structured = self.parser.parse_event(raw)
                if not structured:
                    continue
                if structured["verified"]:
                    self._route_audit(structured)
        except Exception as e:
            logger.error(f"[AUDIT_WATCH] Failed to process audit log: {e}")

    def _route_audit(self, event: dict):
        logger.info(f"[AUDIT_WATCHER] Routing audit event: {event['event_type']}")
        if event["event_type"] in {"unauthorized_access", "privilege_escalation", "rbac_violation"}:
            send_telegram_alert(event)
        if event["event_type"] == "data_exfiltration":
            auto_silence_event(event)
            schedule_replay(event)

class AuditWatcher:
    def __init__(self, log_path: str = AUDIT_LOG_PATH, source: str = AUDIT_SOURCE):
        self.log_path = log_path
        self.parser = AuditParser(source)
        self.event_handler = AuditEventHandler(self.parser)
        self.observer = Observer()

    @trace_with_context
    def start(self):
        logger.info("[AUDIT_WATCHER] Starting audit log watcher...")
        dirname = os.path.dirname(self.log_path)
        self.observer.schedule(self.event_handler, dirname, recursive=False)
        self.observer.start()
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

def launch_watcher_async():
    watcher = AuditWatcher()
    thread = threading.Thread(target=watcher.start, daemon=True)
    thread.start()
    logger.info("[AUDIT_WATCHER] Launched in background thread")
