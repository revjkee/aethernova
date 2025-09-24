import logging
import numpy as np
from typing import Dict, List, Tuple
from datetime import datetime, timedelta
from collections import deque

from genesisops_core.ai.timeseries import RNNForecaster, seasonal_decompose, detect_anomalies
from genesisops_core.telemetry.metrics import fetch_cpu_load, fetch_mem_usage
from genesisops_core.utils.math import exponential_weighted_moving_avg
from genesisops_core.control.alerts import trigger_scaling_alert
from genesisops_core.core.errors import LoadPredictionError

logger = logging.getLogger("autoscaler.load_predictor")
logging.basicConfig(level=logging.INFO)

HISTORY_WINDOW = 60  # в минутах
FORECAST_HORIZON = 15  # в минутах
ANOMALY_THRESHOLD = 2.5
CONFIDENCE_MIN = 0.85

class LoadPredictor:
    def __init__(self):
        self.cpu_history = deque(maxlen=HISTORY_WINDOW)
        self.mem_history = deque(maxlen=HISTORY_WINDOW)
        self.forecaster = RNNForecaster(model_name="autoscaler-rnn-v2")

    def collect_metrics(self):
        try:
            cpu = fetch_cpu_load()
            mem = fetch_mem_usage()
            self.cpu_history.append(cpu)
            self.mem_history.append(mem)
            logger.debug(f"Metrics collected: CPU={cpu}, MEM={mem}")
        except Exception as e:
            logger.warning(f"Metric collection failed: {e}")

    def _prepare_series(self, data: deque) -> np.ndarray:
        arr = np.array(data)
        if len(arr) < 10:
            raise LoadPredictionError("Insufficient history for prediction")
        return exponential_weighted_moving_avg(arr, alpha=0.3)

    def _forecast_load(self, series: np.ndarray) -> Tuple[List[float], float]:
        try:
            season, trend = seasonal_decompose(series)
            anomalies = detect_anomalies(series)
            forecast, confidence = self.forecaster.predict(series[-30:])

            if confidence < CONFIDENCE_MIN:
                raise LoadPredictionError("Confidence too low")

            if len(anomalies) > 0 and max(anomalies) > ANOMALY_THRESHOLD:
                trigger_scaling_alert("Anomaly detected in load pattern")

            return forecast.tolist(), confidence
        except Exception as e:
            logger.error(f"Forecasting failed: {e}")
            raise LoadPredictionError("Load prediction failed") from e

    def predict_next_window(self) -> Dict[str, Dict]:
        try:
            cpu_series = self._prepare_series(self.cpu_history)
            mem_series = self._prepare_series(self.mem_history)

            cpu_forecast, cpu_conf = self._forecast_load(cpu_series)
            mem_forecast, mem_conf = self._forecast_load(mem_series)

            prediction = {
                "timestamp": datetime.utcnow().isoformat(),
                "cpu_forecast": {
                    "values": cpu_forecast,
                    "confidence": cpu_conf
                },
                "mem_forecast": {
                    "values": mem_forecast,
                    "confidence": mem_conf
                }
            }

            logger.info(f"Prediction generated: CPU={cpu_forecast}, MEM={mem_forecast}")
            return prediction

        except LoadPredictionError as e:
            logger.warning(f"Prediction warning: {e}")
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
