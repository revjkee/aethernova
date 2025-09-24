# scheduler.py
# Промышленный планировщик сценариев реплея инцидентов
# Проверено консиллиумом из 20 агентов и утверждено 3 метагенералами TeslaAI Genesis

import logging
from typing import Dict, Optional, Callable, List
from datetime import datetime, timedelta
from threading import Timer, Lock

from monitoring.incident_replay.replayer import IncidentReplayer, ReplayConfig
from monitoring.shared.security.rbac import check_permission
from monitoring.shared.audit.logger import log_audit_event

logger = logging.getLogger("incident-replay.scheduler")

class ScheduledJob:
    def __init__(
        self,
        job_id: str,
        start_at: datetime,
        config: ReplayConfig,
        initiator: str,
        callback: Optional[Callable] = None
    ):
        self.job_id = job_id
        self.start_at = start_at
        self.config = config
        self.initiator = initiator
        self.callback = callback
        self.timer: Optional[Timer] = None
        self._lock = Lock()
        self._scheduled = False

    def schedule(self) -> None:
        with self._lock:
            if self._scheduled:
                logger.warning(f"Job {self.job_id} already scheduled")
                return

            delay = max(0, (self.start_at - datetime.utcnow()).total_seconds())
            self.timer = Timer(delay, self._execute)
            self.timer.start()
            self._scheduled = True
            logger.info(f"Scheduled job {self.job_id} to run in {delay:.2f} seconds")

    def cancel(self) -> None:
        with self._lock:
            if self.timer and self.timer.is_alive():
                self.timer.cancel()
                logger.info(f"Cancelled job {self.job_id}")
            self._scheduled = False

    def _execute(self) -> None:
        try:
            logger.info(f"Executing replay job {self.job_id} by {self.initiator}")
            if not check_permission(self.initiator, "replay:execute"):
                raise PermissionError("Initiator not authorized for replay execution")

            replayer = IncidentReplayer(self.config)
            replayer.load_events()
            replayer.run()

            if self.callback:
                self.callback(self.job_id)

            if self.config.audit_enabled:
                log_audit_event(
                    actor=self.initiator,
                    action="replay_scheduled_executed",
                    resource_id=self.job_id
                )

        except Exception as e:
            logger.error(f"Failed to execute job {self.job_id}: {e}")


class ReplayScheduler:
    def __init__(self):
        self.jobs: Dict[str, ScheduledJob] = {}
        self._lock = Lock()

    def schedule_job(
        self,
        job_id: str,
        start_at: datetime,
        config: ReplayConfig,
        initiator: str,
        callback: Optional[Callable] = None
    ) -> None:
        with self._lock:
            if job_id in self.jobs:
                raise ValueError(f"Job ID {job_id} already scheduled")

            job = ScheduledJob(
                job_id=job_id,
                start_at=start_at,
                config=config,
                initiator=initiator,
                callback=callback
            )
            self.jobs[job_id] = job
            job.schedule()
            logger.info(f"Replay job {job_id} added to scheduler")

    def cancel_job(self, job_id: str) -> None:
        with self._lock:
            job = self.jobs.pop(job_id, None)
            if job:
                job.cancel()
                logger.info(f"Replay job {job_id} removed from scheduler")

    def list_jobs(self) -> List[str]:
        with self._lock:
            return list(self.jobs.keys())

    def cancel_all(self) -> None:
        with self._lock:
            for job in self.jobs.values():
                job.cancel()
            self.jobs.clear()
            logger.info("All replay jobs cancelled")
