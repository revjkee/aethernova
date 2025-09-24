import json
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class FeedParser:
    def __init__(self, feed_format: str = 'json'):
        self.feed_format = feed_format.lower()

    def parse(self, raw_data: str) -> Optional[List[Dict]]:
        """
        Разбор сырых данных из фидов угроз.
        Поддерживаются форматы JSON и plain text (каждая строка - отдельный индикатор).

        :param raw_data: сырые данные из фида
        :return: список словарей с индикаторами угроз или None при ошибке
        """
        try:
            if self.feed_format == 'json':
                data = json.loads(raw_data)
                # Ожидаем, что данные содержат список индикаторов под ключом "indicators"
                indicators = data.get('indicators')
                if not isinstance(indicators, list):
                    logger.error("JSON feed не содержит список индикаторов в ключе 'indicators'")
                    return None
                return indicators

            elif self.feed_format == 'text':
                lines = raw_data.strip().splitlines()
                indicators = [{'indicator': line.strip()} for line in lines if line.strip()]
                return indicators

            else:
                logger.error(f"Unsupported feed format: {self.feed_format}")
                return None

        except json.JSONDecodeError as e:
            logger.error(f"Ошибка при разборе JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"Неизвестная ошибка при разборе фида: {e}")
            return None


# Пример использования
if __name__ == "__main__":
    sample_json = '''
    {
        "indicators": [
            {"type": "ip", "value": "192.168.1.1"},
            {"type": "domain", "value": "malicious.example.com"}
        ]
    }
    '''

    parser = FeedParser(feed_format='json')
    indicators = parser.parse(sample_json)
    if indicators:
        for ind in indicators:
            print(f"Type: {ind.get('type')}, Value: {ind.get('value')}")
    else:
        print("Не удалось распарсить фид.")
