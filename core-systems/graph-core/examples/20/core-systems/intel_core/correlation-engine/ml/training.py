# intel-core/correlation-engine/ml/training.py

import os
import json
from typing import List, Dict, Any
import joblib

from anomaly_detection_model import AnomalyDetectionModel

class ModelTrainer:
    """
    Класс для обучения и сохранения моделей корреляции и обнаружения аномалий.
    """

    def __init__(self, model_save_path: str):
        self.model_save_path = model_save_path
        self.model = AnomalyDetectionModel()

    def load_training_data(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Загрузка тренировочных данных из JSON-файла.

        :param filepath: путь к файлу с данными
        :return: список словарей с признаками
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data

    def train(self, data: List[Dict[str, Any]], feature_keys: List[str]) -> None:
        """
        Обучение модели на тренировочных данных.

        :param data: список словарей с признаками
        :param feature_keys: ключи признаков для обучения
        """
        self.model.fit(data, feature_keys)

    def save_model(self) -> None:
        """
        Сохранение обученной модели на диск.
        """
        os.makedirs(os.path.dirname(self.model_save_path), exist_ok=True)
        joblib.dump(self.model, self.model_save_path)

    def load_model(self) -> None:
        """
        Загрузка модели с диска.
        """
        if os.path.exists(self.model_save_path):
            self.model = joblib.load(self.model_save_path)
        else:
            raise FileNotFoundError(f"Модель не найдена по пути: {self.model_save_path}")


# Пример использования (без запуска при импорте)
if __name__ == "__main__":
    trainer = ModelTrainer(model_save_path='models/anomaly_detection_model.pkl')

    training_data = trainer.load_training_data('data/training_data.json')
    features = ['feature1', 'feature2', 'feature3']  # заменить на реальные ключи

    trainer.train(training_data, features)
    trainer.save_model()
