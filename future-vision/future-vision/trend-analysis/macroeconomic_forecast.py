# macroeconomic_forecast.py

"""
TeslaAI Genesis :: FutureVision Module — Macroeconomic Forecasting Engine
Модуль: AI-модель прогнозирования макроэкономических тенденций
Версия: Industrial+ (vX.20 Enhanced)
Авторизация: Одобрено 3 метагенералами и 20 AI-агентами
"""

import pandas as pd
import numpy as np
import logging
from datetime import datetime
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from typing import Dict, Any

from future_vision.utils.data_sources import fetch_global_macro_data
from future_vision.utils.signal_fusion import integrate_geo_esg_behavioral_signals
from future_vision.utils.forecast_utils import forecast_horizon_split, postprocess_forecast
from future_vision.validation.economic_integrity_guard import EconomicModelIntegrityValidator

logger = logging.getLogger("MacroeconomicForecast")
logger.setLevel(logging.INFO)

class MacroeconomicForecastEngine:
    def __init__(self, forecast_target: str = "gdp_growth"):
        self.forecast_target = forecast_target
        self.model = self._build_pipeline()
        self.validator = EconomicModelIntegrityValidator()

    def _build_pipeline(self) -> Pipeline:
        """
        Строит промышленный AI-конвейер обработки и прогноза.
        """
        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("regressor", GradientBoostingRegressor(
                n_estimators=300,
                learning_rate=0.05,
                max_depth=6,
                subsample=0.9,
                random_state=42
            ))
        ])
        return pipeline

    def prepare_dataset(self) -> pd.DataFrame:
        """
        Загружает и объединяет макроэкономические, ESG и геополитические данные.
        """
        base_df = fetch_global_macro_data()
        enriched_df = integrate_geo_esg_behavioral_signals(base_df)
        enriched_df = enriched_df.dropna()
        logger.info(f"[Forecast] Данные подготовлены: {enriched_df.shape}")
        return enriched_df

    def train_model(self, data: pd.DataFrame) -> None:
        """
        Обучает модель на исторических данных.
        """
        X_train, X_test, y_train, y_test = forecast_horizon_split(data, self.forecast_target)
        self.model.fit(X_train, y_train)
        score = self.model.score(X_test, y_test)
        logger.info(f"[Forecast] Обучение завершено. Точность модели (R²): {score:.4f}")

        # Проверка валидности и недопущения этических нарушений
        if not self.validator.validate(self.model, X_test, y_test):
            raise ValueError("[Forecast] Модель не прошла аудит экономической устойчивости")

    def generate_forecast(self, future_inputs: pd.DataFrame) -> pd.DataFrame:
        """
        Генерирует прогноз макроэкономического показателя.
        """
        prediction = self.model.predict(future_inputs)
        result = postprocess_forecast(prediction, self.forecast_target)
        logger.info(f"[Forecast] Прогноз сгенерирован.")
        return result

    def forecast_from_live_data(self) -> pd.DataFrame:
        """
        Конвейер прогнозирования с использованием live-данных.
        """
        try:
            df = self.prepare_dataset()
            self.train_model(df)
            latest_input = df.tail(1).drop(columns=[self.forecast_target])
            return self.generate_forecast(latest_input)
        except Exception as e:
            logger.error(f"[Forecast] Ошибка при прогнозировании: {e}")
            return pd.DataFrame()

