import time
import os
import logging
import pandas as pd
from datetime import datetime
from hr_ai.prediction.performance_model import PerformancePredictor
from hr_ai.utils.monitoring.drift_detector import detect_drift
from hr_ai.utils.versioning.model_registry import (
    register_model_version,
    archive_previous_model,
    get_latest_model_path,
)
from hr_ai.utils.security.audit import secure_log
from hr_ai.utils.config import load_yaml_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RetrainingLoop")

CONFIG_PATH = "hr_ai/config/retraining_config.yaml"
DATA_SOURCE_PATH = "data/hr_live_data.csv"
MODEL_SAVE_DIR = "models/"
DRIFT_THRESHOLD = 0.15

def load_data(path: str) -> pd.DataFrame:
    try:
        data = pd.read_csv(path)
        logger.info(f"Loaded {len(data)} records from {path}")
        return data
    except Exception as e:
        logger.error(f"Failed to load data: {e}")
        return pd.DataFrame()

def retrain_model(data: pd.DataFrame, config: dict) -> str:
    model = PerformancePredictor(config=config)
    model.train(data)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_path = os.path.join(MODEL_SAVE_DIR, f"performance_model_{timestamp}.pkl")
    model.save_model(model_path)
    logger.info(f"Model retrained and saved to {model_path}")
    return model_path

def retraining_loop():
    config = load_yaml_config(CONFIG_PATH)
    poll_interval = config.get("poll_interval_seconds", 86400)
    
    while True:
        logger.info("Retraining cycle started")
        data = load_data(DATA_SOURCE_PATH)
        if data.empty:
            logger.warning("No data found. Skipping retraining.")
            time.sleep(poll_interval)
            continue

        baseline_model_path = get_latest_model_path()
        drift_score = detect_drift(data, baseline_model_path)

        if drift_score >= DRIFT_THRESHOLD:
            secure_log("Drift detected", context={"score": drift_score})
            new_model_path = retrain_model(data, config.get("model_params", {}))
            archive_previous_model(baseline_model_path)
            register_model_version(new_model_path)
        else:
            logger.info(f"No significant drift detected (score: {drift_score}). Skipping retrain.")

        logger.info(f"Sleeping for {poll_interval} seconds before next cycle")
        time.sleep(poll_interval)

if __name__ == "__main__":
    retraining_loop()
