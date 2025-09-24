"""
llmops.tuning.evaluators.scorer

Метрики для пост-оценки дообученных моделей:
- вычисление reward
- расчет потерь (loss)
- оценка дивергенции распределений
- KL-дивергенция и др.
"""

import numpy as np
from typing import List, Optional


def compute_reward(predictions: List[float], targets: List[float]) -> float:
    """
    Вычисляет средний reward для предсказаний модели.
    :param predictions: список числовых значений предсказаний
    :param targets: список целевых значений reward
    :return: среднее значение reward
    """
    if len(predictions) != len(targets):
        raise ValueError("Длины predictions и targets должны совпадать")
    rewards = np.array(predictions) * np.array(targets)
    return float(np.mean(rewards))


def compute_loss(logits: List[float], labels: List[int]) -> float:
    """
    Вычисляет среднее значение бинарной кросс-энтропии (loss).
    :param logits: предсказанные логиты модели
    :param labels: истинные метки (0 или 1)
    :return: среднее значение loss
    """
    logits = np.array(logits)
    labels = np.array(labels)
    eps = 1e-12
    logits = np.clip(logits, eps, 1 - eps)
    loss = - labels * np.log(logits) - (1 - labels) * np.log(1 - logits)
    return float(np.mean(loss))


def kl_divergence(p: List[float], q: List[float]) -> float:
    """
    Рассчитывает KL-дивергенцию между двумя распределениями p и q.
    :param p: истинное распределение вероятностей
    :param q: аппроксимация распределения
    :return: значение KL-дивергенции
    """
    p = np.array(p)
    q = np.array(q)
    eps = 1e-12
    p = np.clip(p, eps, 1)
    q = np.clip(q, eps, 1)
    return float(np.sum(p * np.log(p / q)))


def jensen_shannon_divergence(p: List[float], q: List[float]) -> float:
    """
    Вычисляет дивергенцию Дженсена-Шеннона между распределениями p и q.
    :param p: первое распределение вероятностей
    :param q: второе распределение вероятностей
    :return: значение JS-дивергенции
    """
    import math

    def _entropy(dist):
        dist = np.array(dist)
        eps = 1e-12
        dist = np.clip(dist, eps, 1)
        return -np.sum(dist * np.log2(dist))

    m = 0.5 * (np.array(p) + np.array(q))
    return 0.5 * (_entropy(p) + _entropy(q)) - _entropy(m)


if __name__ == "__main__":
    # Тестовые проверки функций
    preds = [0.8, 0.4, 0.9]
    targets = [1.0, 0.0, 1.0]
    print("Reward:", compute_reward(preds, targets))

    logits = [0.9, 0.1, 0.8, 0.4]
    labels = [1, 0, 1, 0]
    print("Loss:", compute_loss(logits, labels))

    p = [0.1, 0.9]
    q = [0.2, 0.8]
    print("KL Divergence:", kl_divergence(p, q))
    print("JS Divergence:", jensen_shannon_divergence(p, q))
