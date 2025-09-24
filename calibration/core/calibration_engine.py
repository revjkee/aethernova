import logging
import threading
from typing import Dict, Any, Optional, Callable
from uuid import uuid4
from datetime import datetime

from calibration.core.models import CalibrationTask, CalibrationResult
from calibration.core.metrics import fetch_live_metrics
from calibration.core.persistence import save_result
from calibration.core.strategies import AdaptiveCalibrationStrategy
from calibration.core.exceptions import CalibrationValidationError

logger = logging.getLogger("calibration")
logger.setLevel(logging.INFO)

class CalibrationEngine:
    def __init__(self,
                 strategy: Optional[AdaptiveCalibrationStrategy] = None,
                 metric_fetcher: Callable[[], Dict[str, Any]] = fetch_live_metrics,
                 result_saver: Callable[[CalibrationResult], None] = save_result):
        self.strategy = strategy or AdaptiveCalibrationStrategy()
        self.metric_fetcher = metric_fetcher
        self.result_saver = result_saver
        self._active_tasks: Dict[str, CalibrationTask] = {}
        self._lock = threading.Lock()

    def run_calibration(self, parameters: Dict[str, Any]) -> CalibrationResult:
        task_id = str(uuid4())
        logger.info(f"[{task_id}] Starting calibration with parameters: {parameters}")
        start_time = datetime.utcnow()

        try:
            self._validate_parameters(parameters)
            metrics_before = self.metric_fetcher()
            logger.debug(f"[{task_id}] Metrics before calibration: {metrics_before}")

            optimized_params = self.strategy.calibrate(parameters, metrics_before)
            metrics_after = self.metric_fetcher()
            logger.debug(f"[{task_id}] Metrics after calibration: {metrics_after}")

            result = CalibrationResult(
                task_id=task_id,
                parameters=parameters,
                optimized_parameters=optimized_params,
                metrics_before=metrics_before,
                metrics_after=metrics_after,
                timestamp=start_time
            )

            self.result_saver(result)
            logger.info(f"[{task_id}] Calibration completed successfully.")
            return result

        except CalibrationValidationError as e:
            logger.error(f"[{task_id}] Validation failed: {str(e)}")
            raise

        except Exception as e:
            logger.exception(f"[{task_id}] Calibration failed with unexpected error.")
            raise

    def _validate_parameters(self, parameters: Dict[str, Any]):
        if not parameters or not isinstance(parameters, dict):
            raise CalibrationValidationError("Parameters must be a non-empty dictionary.")
        if "target" not in parameters:
            raise CalibrationValidationError("Missing 'target' parameter.")
        logger.debug("Parameters validated successfully.")

    def get_active_tasks(self) -> Dict[str, CalibrationTask]:
        with self._lock:
            return dict(self._active_tasks)

    def start_background_task(self, parameters: Dict[str, Any]) -> str:
        task_id = str(uuid4())

        def _run():
            try:
                result = self.run_calibration(parameters)
                logger.info(f"[{task_id}] Background calibration result: {result}")
            except Exception as e:
                logger.error(f"[{task_id}] Background calibration failed: {e}")

        with self._lock:
            self._active_tasks[task_id] = CalibrationTask(task_id, parameters, datetime.utcnow())

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        logger.info(f"[{task_id}] Background calibration task started.")
        return task_id
