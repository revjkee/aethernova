# intel-core/correlation-engine/ml/inference.py

import os
from typing import List, Dict, Any
import joblib

class ModelInference:
    """
    Класс для загрузки обученной модели и выполнения инференса на новых данных.
    """

    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        self.load_model()

    def load_model(self) -> None:
        """
        Загрузка модели с диска.
        """
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Модель не найдена по пути: {self.model_path}")
        self.model = joblib.load(self.model_path)

    def predict(self, data: List[Dict[str, Any]], feature_keys: List[str]) -> List[Any]:
        """
        Прогнозирование на новых данных.

        :param data: список словарей с признаками
        :param feature_keys: ключи признаков, используемых моделью
        :return: список предсказаний модели (например, метки аномалий)
        """
        if self.model is None:
            raise ValueError("Модель не загружена")

        # Подготовка данных в формате, который ожидает модель
        features = []
        for entry in data:
            features.append([entry.get(key, 0) for key in feature_keys])

        return self.model.predict(features)


# Пример использования (без запуска при импорте)
if __name__ == "__main__":
    inference = ModelInference(model_path='models/anomaly_detection_model.pkl')

    sample_data = [
        {'feature1': 0.5, 'feature2': 1.2, 'feature3': 0.0},
        {'feature1': 1.5, 'feature2': 0.2, 'feature3': 3.3},
    ]
    features = ['feature1', 'feature2', 'feature3']

    predictions = inference.predict(sample_data, features)
    print("Предсказания модели:")
    for pred in predictions:
        print(pred)
