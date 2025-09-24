import json
import logging
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any
from sklearn.metrics import precision_score, recall_score
from sklearn.preprocessing import LabelEncoder

from .report_utils import generate_bias_report

logger = logging.getLogger("bias_auditor")
logger.setLevel(logging.INFO)

PROTECTED_ATTRIBUTES = ["gender", "ethnicity", "age_group", "disability_status"]

class BiasAuditor:
    def __init__(self, data_path: str, label_column: str = "hired", log_file: str = "bias_audit_results.jsonl"):
        self.data_path = data_path
        self.label_column = label_column
        self.log_file = log_file
        self.encoder_cache = {}

    def _load_data(self) -> pd.DataFrame:
        try:
            df = pd.read_csv(self.data_path)
            logger.info(f"Loaded {len(df)} records from {self.data_path}")
            return df
        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            return pd.DataFrame()

    def _encode_column(self, df: pd.DataFrame, column: str) -> pd.Series:
        if column not in self.encoder_cache:
            le = LabelEncoder()
            self.encoder_cache[column] = le.fit(df[column].astype(str))
        return self.encoder_cache[column].transform(df[column].astype(str))

    def _groupwise_metrics(self, df: pd.DataFrame, protected_attr: str) -> Dict[str, Any]:
        groups = df[protected_attr].unique()
        results = {}
        for group in groups:
            group_df = df[df[protected_attr] == group]
            y_true = group_df["true_label"]
            y_pred = group_df["predicted_label"]
            results[group] = {
                "count": len(group_df),
                "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
                "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
                "selection_rate": round(sum(y_pred) / len(y_pred), 4) if len(y_pred) > 0 else 0.0
            }
        return results

    def audit(self) -> Dict[str, Any]:
        df = self._load_data()
        if df.empty:
            return {"status": "error", "reason": "data load failure"}

        df["true_label"] = self._encode_column(df, self.label_column)
        df["predicted_label"] = self._encode_column(df, "predicted")

        audit_results = {}
        for attr in PROTECTED_ATTRIBUTES:
            if attr not in df.columns:
                logger.warning(f"Protected attribute '{attr}' not found in dataset.")
                continue

            attr_result = self._groupwise_metrics(df, attr)
            audit_results[attr] = attr_result
            logger.info(f"Audited bias on attribute '{attr}'")

        self._log_results(audit_results)
        generate_bias_report(audit_results)
        return audit_results

    def _log_results(self, results: Dict[str, Any]):
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps({
                    "timestamp": datetime.utcnow().isoformat(),
                    "results": results
                }) + "\n")
            logger.info("Audit results logged.")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
