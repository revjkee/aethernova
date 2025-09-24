import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import deque, defaultdict
import re

from sklearn.ensemble import IsolationForest
import numpy as np

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Конфигурация по умолчанию
WINDOW_SIZE = 1000  # Кол-во последних логов для анализа
ANOMALY_THRESHOLD = 0.7  # Порог аномалии для AI модели
MIN_LOG_LENGTH = 5  # Игнорируем короткие сообщения
FAILED_KEYWORDS = ['fail', 'error', 'unauthorized', 'denied', 'timeout']

# Очередь логов
log_window = deque(maxlen=WINDOW_SIZE)

# Модель AI (IsolationForest для поведенческого анализа)
model = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
trained = False


def preprocess_log(entry: Dict[str, Any]) -> List[float]:
    """
    Преобразует лог-запись в числовой вектор признаков.
    """
    ts = datetime.fromisoformat(entry.get("timestamp", datetime.utcnow().isoformat()))
    seconds = ts.timestamp() % 86400  # Секунды с начала суток
    msg = entry.get("message", "")
    level = entry.get("level", "INFO")

    return [
        seconds / 86400.0,
        len(msg) / 1000.0,
        int(level == "ERROR") + int(level == "CRITICAL"),
        int(any(k in msg.lower() for k in FAILED_KEYWORDS))
    ]


def detect_anomalies(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    global trained
    vectors = [preprocess_log(e) for e in entries if len(e.get("message", "")) >= MIN_LOG_LENGTH]

    if len(vectors) < 20:
        logger.debug("Недостаточно данных для анализа.")
        return []

    X = np.array(vectors)

    # Обучение модели при первом запуске
    if not trained:
        model.fit(X)
        trained = True
        logger.info("AI модель аномалий обучена.")

    preds = model.decision_function(X)  # Чем меньше значение, тем выше вероятность аномалии
    result = []

    for i, score in enumerate(preds):
        if score < -ANOMALY_THRESHOLD:
            anomaly = entries[i].copy()
            anomaly["anomaly_score"] = float(score)
            anomaly["detected"] = True
            result.append(anomaly)

    return result


def log_anomalies(anomalies: List[Dict[str, Any]]):
    for a in anomalies:
        logger.warning(
            "[АНОМАЛИЯ] [%s] %s (score=%.4f)",
            a.get("timestamp"),
            a.get("message", ""),
            a.get("anomaly_score", 0.0)
        )


def process_log_entry(entry: Dict[str, Any]):
    log_window.append(entry)
    if len(log_window) >= WINDOW_SIZE // 2:
        anomalies = detect_anomalies(list(log_window))
        if anomalies:
            log_anomalies(anomalies)


def process_raw_log_line(line: str):
    """
    Обработка сырой строки лога (например, из stdout или файла).
    """
    try:
        data = json.loads(line)
        process_log_entry(data)
    except json.JSONDecodeError:
        logger.debug("Пропущена невалидная строка: %s", line[:100])


def check_for_known_patterns(message: str) -> bool:
    """
    Проверка на известные вредоносные сигнатуры (регулярки).
    """
    patterns = [
        r"(\/etc\/passwd|\/bin\/sh|\/dev\/null)",
        r"(SELECT\s+\*\s+FROM\s+\w+)",
        r"(wget|curl)\s+https?:\/\/",
        r"(base64\s+-d|eval\()",
        r"0x[0-9a-fA-F]{8,}"  # подозрительные hex-данные
    ]
    for pattern in patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return True
    return False


def enhanced_anomaly_check(entry: Dict[str, Any]) -> bool:
    """
    Расширенная проверка логов с учётом сигнатур.
    """
    msg = entry.get("message", "")
    return check_for_known_patterns(msg) or "anomaly_score" in entry


# Пример вызова
if __name__ == "__main__":
    with open("gateway_logs/test_logs.jsonl", "r", encoding="utf-8") as f:
        for line in f:
            process_raw_log_line(line)
