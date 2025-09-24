# intel-core/correlation-engine/tests/integration/test_correlation_flow.py

import unittest
import asyncio
from correlation_engine.engines.event_processor import EventProcessor
from correlation_engine.engines.rule_evaluator import RuleEvaluator
from correlation_engine.engines.correlation_manager import CorrelationManager

class TestCorrelationFlow(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.event_processor = EventProcessor()
        self.rule_evaluator = RuleEvaluator()
        self.correlation_manager = CorrelationManager()

        # Инициализация и загрузка правил (можно мокать, но здесь реальная загрузка)
        await self.rule_evaluator.load_rules('intel-core/correlation-engine/rules/detection_rules.yaml')

    async def test_full_correlation_cycle(self):
        # Создаём тестовое событие
        test_event = {
            'timestamp': '2025-07-18T16:00:00Z',
            'event_type': 'login_failed',
            'source_ip': '192.168.1.100',
            'user': 'admin'
        }

        # Обработка события
        processed_event = await self.event_processor.process_event(test_event)
        self.assertIsNotNone(processed_event)

        # Оценка правил по событию
        matched_rules = await self.rule_evaluator.evaluate(processed_event)
        self.assertIsInstance(matched_rules, list)

        # Запуск корреляции по найденным правилам
        alerts = await self.correlation_manager.correlate(matched_rules, processed_event)
        self.assertIsInstance(alerts, list)

        # Проверка, что хотя бы одно оповещение создано при совпадении правил
        if matched_rules:
            self.assertGreater(len(alerts), 0)
        else:
            self.assertEqual(len(alerts), 0)

if __name__ == '__main__':
    unittest.main()
