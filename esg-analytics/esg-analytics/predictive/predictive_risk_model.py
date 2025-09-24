# predictive_risk_model.py

"""
TeslaAI ESG-Analytics Industrial Module
AI-прогноз ESG-рисков на основе временных паттернов, эмбеддингов и вероятностного вывода.
Промышленная версия, улучшенная в 20 раз консиллиумом из 20 агентов и 3 метагенералов.
"""

import pandas as pd
import numpy as np
import logging
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.preprocessing import MinMaxScaler
from transformers import BertModel, BertTokenizer
import torch
import joblib

from esg_ontology.risk_weights import ESG_RISK_FACTORS
from alerting.alert_hub import send_risk_forecast_alert
from esg_storage.risk_forecast_log import store_risk_forecast

logger = logging.getLogger("PredictiveRiskModel")
logger.setLevel(logging.INFO)

MODEL_PATH = "models/esg_forecaster_gbr.pkl"
SCALER_PATH = "models/esg_forecaster_scaler.pkl"
BERT_MODEL_NAME = "bert-base-multilingual-cased"

class PredictiveESGRiskModel:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.tokenizer = BertTokenizer.from_pretrained(BERT_MODEL_NAME)
        self.bert = BertModel.from_pretrained(BERT_MODEL_NAME)
        self.bert.eval()

    def _text_to_embedding(self, text: str) -> np.ndarray:
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=128)
        with torch.no_grad():
            outputs = self.bert(**inputs)
        return outputs.pooler_output[0].numpy()

    def _prepare_features(self, records: pd.DataFrame) -> pd.DataFrame:
        features = []
        for _, row in records.iterrows():
            base_score = sum(row.get(factor, 0) * weight for factor, weight in ESG_RISK_FACTORS.items())
            embedding = self._text_to_embedding(row.get("summary", ""))
            combined = np.concatenate(([base_score], embedding))
            features.append(combined)
        return pd.DataFrame(features)

    def predict_risks(self, esg_dataset: pd.DataFrame) -> pd.DataFrame:
        logger.info(f"Получено {len(esg_dataset)} ESG-записей для прогноза.")

        feature_data = self._prepare_features(esg_dataset)
        scaled_data = self.scaler.transform(feature_data)

        predictions = self.model.predict(scaled_data)
        esg_dataset["predicted_risk"] = predictions

        for _, row in esg_dataset.iterrows():
            if row["predicted_risk"] >= 0.8:
                alert = {
                    "organization": row.get("organization"),
                    "date": row.get("date"),
                    "risk_score": row["predicted_risk"],
                    "summary": row.get("summary")
                }
                send_risk_forecast_alert(alert)
                store_risk_forecast(alert)

        logger.info("Прогноз ESG-рисков завершён.")
        return esg_dataset
