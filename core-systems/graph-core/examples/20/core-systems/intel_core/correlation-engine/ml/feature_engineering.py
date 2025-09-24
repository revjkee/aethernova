# intel-core/correlation-engine/ml/feature_engineering.py

from typing import List, Dict, Any
import datetime

def extract_basic_features(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Извлекает базовые признаки из списка событий.
    Пример признаков: час события, день недели, длина строки поля 'message', количество уникальных IP и т.п.

    :param events: список событий (каждое событие — словарь с произвольными полями)
    :return: список словарей с признаками для каждого события
    """
    features_list = []
    for event in events:
        features = {}

        # Время события — преобразуем в признаки времени
        timestamp = event.get('timestamp')
        if timestamp:
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.datetime.fromisoformat(timestamp)
                except Exception:
                    timestamp = None
            if isinstance(timestamp, datetime.datetime):
                features['hour'] = timestamp.hour
                features['weekday'] = timestamp.weekday()
            else:
                features['hour'] = -1
                features['weekday'] = -1
        else:
            features['hour'] = -1
            features['weekday'] = -1

        # Пример извлечения признаков из поля message
        message = event.get('message', '')
        features['message_length'] = len(message)
        features['message_word_count'] = len(message.split())

        # Дополнительные признаки (если есть IP)
        src_ip = event.get('src_ip', '')
        dst_ip = event.get('dst_ip', '')
        features['src_ip_length'] = len(src_ip)
        features['dst_ip_length'] = len(dst_ip)

        # Можно добавить здесь и другие признаки из события по необходимости

        features_list.append(features)

    return features_list


def aggregate_features(events: List[Dict[str, Any]], key_field: str) -> Dict[str, Dict[str, Any]]:
    """
    Аггрегация признаков по ключевому полю (например, IP).
    Считаем количество событий, среднюю длину сообщений и т.п. для каждой группы.

    :param events: список событий
    :param key_field: поле для группировки (например, 'src_ip')
    :return: словарь, где ключ — значение key_field, а значение — агрегированные признаки
    """
    from collections import defaultdict

    agg_data = defaultdict(lambda: {
        'event_count': 0,
        'total_message_length': 0,
        'total_word_count': 0
    })

    for event in events:
        key = event.get(key_field)
        if key is None:
            continue

        message = event.get('message', '')
        agg_data[key]['event_count'] += 1
        agg_data[key]['total_message_length'] += len(message)
        agg_data[key]['total_word_count'] += len(message.split())

    # Вычисляем средние значения
    for key, data in agg_data.items():
        count = data['event_count']
        data['avg_message_length'] = data['total_message_length'] / count if count else 0
        data['avg_word_count'] = data['total_word_count'] / count if count else 0

    return agg_data

