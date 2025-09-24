import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

class Correlator:
    def __init__(self):
        # Хранилище для индикаторов, сгруппированных по типу и значению
        self.indicators_store = defaultdict(list)

    def add_indicators(self, indicators: List[Dict[str, Any]]) -> None:
        """
        Добавить список индикаторов в хранилище для последующей корреляции.

        :param indicators: список словарей с ключами 'type' и 'value'
        """
        for ind in indicators:
            try:
                ind_type = ind['type']
                ind_value = ind['value']
                self.indicators_store[(ind_type, ind_value)].append(ind)
            except KeyError:
                logger.warning(f"Индикатор пропущен из-за отсутствия ключей 'type' или 'value': {ind}")

    def correlate(self) -> List[Dict[str, Any]]:
        """
        Корреляция индикаторов, объединение повторяющихся и выявление связей.

        В текущей реализации агрегирует индикаторы по типу и значению,
        возвращает уникальные индикаторы с количеством повторений.

        :return: список словарей с полями 'type', 'value' и 'count'
        """
        correlated = []
        for (ind_type, ind_value), ind_list in self.indicators_store.items():
            correlated.append({
                'type': ind_type,
                'value': ind_value,
                'count': len(ind_list)
            })
        return correlated

    def find_related(self, indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Поиск индикаторов, связанных с данным, например, по типу.

        :param indicator: словарь с 'type' и 'value'
        :return: список связанных индикаторов
        """
        ind_type = indicator.get('type')
        if not ind_type:
            logger.warning(f"В индикаторе нет типа: {indicator}")
            return []

        related = []
        for (t, v), inds in self.indicators_store.items():
            if t == ind_type and v != indicator.get('value'):
                related.append({'type': t, 'value': v, 'count': len(inds)})
        return related


# Пример использования
if __name__ == "__main__":
    sample_indicators = [
        {'type': 'ip', 'value': '192.168.1.1'},
        {'type': 'ip', 'value': '192.168.1.1'},
        {'type': 'domain', 'value': 'malicious.example.com'},
        {'type': 'ip', 'value': '10.0.0.1'},
    ]

    correlator = Correlator()
    correlator.add_indicators(sample_indicators)

    correlated = correlator.correlate()
    print("Коррелированные индикаторы:")
    for ind in correlated:
        print(ind)

    related_to_ip = correlator.find_related({'type': 'ip', 'value': '192.168.1.1'})
    print("\nСвязанные с IP индикаторы:")
    for ind in related_to_ip:
        print(ind)
