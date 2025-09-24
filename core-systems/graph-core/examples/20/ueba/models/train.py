# ueba/models/train.py

import os
import argparse
import logging
import numpy as np

from datetime import datetime
from sklearn.model_selection import train_test_split

from ueba.models.anomaly_detector import AnomalyDetector
from ueba.models.metrics import evaluate_metrics
from ueba.features.model_inputs import load_features  # функция должна быть реализована

logger = logging.getLogger("UEBA.Train")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def train_pipeline(
    features_path: str,
    model_save_path: str,
    method: str = "isolation_forest",
    contamination: float = 0.01,
    test_split: float = 0.2,
    random_state: int = 42
):
    logger.info("Загрузка признаков...")
    X, y_true = load_features(features_path)

    logger.info("Деление на train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_true, test_size=test_split, random_state=random_state
    )

    logger.info(f"Инициализация модели: {method}")
    model = AnomalyDetector(
        method=method,
        contamination=contamination,
        random_state=random_state
    )

    logger.info("Обучение модели...")
    model.fit(X_train)

    logger.info("Оценка качества...")
    train_auc = model.evaluate(X_train, y_train)
    test_auc = model.evaluate(X_test, y_test)

    logger.info(f"AUC на обучающей выборке: {train_auc:.4f}")
    logger.info(f"AUC на тестовой выборке: {test_auc:.4f}")

    logger.info("Сохранение модели...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_filename = f"{method}_model_{timestamp}.joblib"
    model_path = os.path.join(model_save_path, model_filename)
    model.save(model_path)

    logger.info(f"Модель сохранена: {model_path}")
    return {
        "train_auc": train_auc,
        "test_auc": test_auc,
        "model_path": model_path
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UEBA Model Trainer")
    parser.add_argument("--features", type=str, required=True, help="Путь до .npy или .parquet признаков")
    parser.add_argument("--output", type=str, required=True, help="Путь для сохранения модели")
    parser.add_argument("--method", type=str, default="isolation_forest", choices=["isolation_forest", "autoencoder"])
    parser.add_argument("--contamination", type=float, default=0.01)
    parser.add_argument("--test_split", type=float, default=0.2)
    parser.add_argument("--random_state", type=int, default=42)

    args = parser.parse_args()

    train_pipeline(
        features_path=args.features,
        model_save_path=args.output,
        method=args.method,
        contamination=args.contamination,
        test_split=args.test_split,
        random_state=args.random_state
    )
