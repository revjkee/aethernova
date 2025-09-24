# mlops/monitoring/drift_detector.py

import os
import logging
import numpy as np
import pandas as pd
from typing import Union, Dict, Any
from scipy.stats import ks_2samp

logger = logging.getLogger("DriftDetector")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(ch)

class DriftDetector:
    def __init__(
        self,
        reference_data: Union[str, pd.DataFrame],
        threshold_psi: float = 0.2,
        threshold_ks: float = 0.1
    ):
        self.threshold_psi = threshold_psi
        self.threshold_ks = threshold_ks
        self.reference = self._load_data(reference_data)
        logger.info("Инициализирован DriftDetector")

    def _load_data(self, source: Union[str, pd.DataFrame]) -> pd.DataFrame:
        if isinstance(source, pd.DataFrame):
            return source
        elif isinstance(source, str):
            ext = os.path.splitext(source)[1]
            if ext == ".json":
                return pd.read_json(source)
            elif ext == ".parquet":
                return pd.read_parquet(source)
            elif ext in [".csv", ".tsv"]:
                return pd.read_csv(source)
            else:
                raise ValueError(f"Неподдерживаемый формат: {ext}")
        else:
            raise ValueError("source должен быть строкой или DataFrame")

    def _calculate_psi(self, expected: np.ndarray, actual: np.ndarray, bins: int = 10) -> float:
        """Расчёт PSI между двумя распределениями"""
        expected_percents, _ = np.histogram(expected, bins=bins, range=(min(expected), max(expected)), density=True)
        actual_percents, _ = np.histogram(actual, bins=bins, range=(min(expected), max(expected)), density=True)
        expected_percents += 1e-6
        actual_percents += 1e-6
        psi = np.sum((expected_percents - actual_percents) * np.log(expected_percents / actual_percents))
        return psi

    def detect(self, new_data: Union[str, pd.DataFrame]) -> Dict[str, Any]:
        current = self._load_data(new_data)
        drift_report = {"drift_detected": False, "features": {}, "summary": {}}

        for column in self.reference.columns:
            if column not in current.columns:
                logger.warning(f"Пропущен столбец {column} (отсутствует в новых данных)")
                continue

            ref_values = self.reference[column].dropna().values
            curr_values = current[column].dropna().values

            if not np.issubdtype(ref_values.dtype, np.number):
                continue  # только числовые фичи

            psi = self._calculate_psi(ref_values, curr_values)
            ks_stat, ks_pvalue = ks_2samp(ref_values, curr_values)

            drift = psi > self.threshold_psi or ks_stat > self.threshold_ks

            drift_report["features"][column] = {
                "psi": round(psi, 4),
                "ks_stat": round(ks_stat, 4),
                "ks_pvalue": round(ks_pvalue, 4),
                "drift": drift
            }

            if drift:
                logger.warning(f"Обнаружен drift в признаке: {column}")

        drift_report["summary"]["total_features"] = len(drift_report["features"])
        drift_report["summary"]["drifted"] = sum(1 for f in drift_report["features"].values() if f["drift"])
        drift_report["drift_detected"] = drift_report["summary"]["drifted"] > 0

        return drift_report
