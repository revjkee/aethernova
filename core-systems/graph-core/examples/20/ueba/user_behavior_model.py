import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging

class UserBehaviorModel:
    """
    Модуль поведенческого анализа пользователей (UEBA).
    Использует Isolation Forest для выявления аномалий в поведении.
    """

    def __init__(self, contamination: float = 0.01):
        """
        :param contamination: Ожидаемая доля аномалий в данных
        """
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=self.contamination, random_state=42)
        self.fitted = False

    def fit(self, features: np.ndarray):
        """
        Обучение модели на исторических данных пользователей.

        :param features: Матрица признаков (n_samples, n_features)
        """
        if features.size == 0:
            logging.error("UserBehaviorModel: Пустой набор данных для обучения")
            return
        scaled = self.scaler.fit_transform(features)
        self.model.fit(scaled)
        self.fitted = True

    def predict(self, features: np.ndarray) -> np.ndarray:
        """
        Предсказание аномалий для новых данных.

        :param features: Матрица признаков новых сессий пользователей
        :return: Массив меток: 1 — нормальное поведение, -1 — аномалия
        """
        if not self.fitted:
            logging.error("UserBehaviorModel: Модель не обучена")
            raise RuntimeError("Model not fitted")
        scaled = self.scaler.transform(features)
        preds = self.model.predict(scaled)
        return preds

    def anomaly_score(self, features: np.ndarray) -> np.ndarray:
        """
        Вычисление степени аномалии (чем ниже — тем более аномально).

        :param features: Матрица признаков
        :return: Массив скорингов аномалий
        """
        if not self.fitted:
            logging.error("UserBehaviorModel: Модель не обучена")
            raise RuntimeError("Model not fitted")
        scaled = self.scaler.transform(features)
        scores = self.model.decision_function(scaled)
        return scores

    def explain(self):
        """
        Метод-заглушка для расширенного объяснения аномалий (можно интегрировать SHAP, LIME и т.п.)
        """
        logging.info("UserBehaviorModel: explain() пока не реализован")

