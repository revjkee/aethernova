# intel-core/correlation-engine/tests/integration/test_rule_engine.py

import unittest
import asyncio
from correlation_engine.engines.rule_evaluator import RuleEvaluator
from correlation_engine.engines.correlation_manager import CorrelationManager

class TestRuleEngineIntegration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.rule_evaluator = RuleEvaluator()
        self.correlation_manager = CorrelationManager()

        # Загружаем реальные правила из YAML
        await self.rule_evaluator.load_rules('intel-core/correlation-engine/rules/detection_rules.yaml')

    async def test_rule_evaluation_and_correlation(self):
        test_event = {
            'timestamp': '2025-07-18T17:00:00Z',
            'event_type': 'file_access',
            'user': 'john_doe',
            'file_path': '/etc/passwd',
            'access_type': 'read'
        }

        # Оценка правил
        matched_rules = await self.rule_evaluator.evaluate(test_event)
        self.assertIsInstance(matched_rules, list)

        # Запуск корреляции по найденным правилам
        alerts = await self.correlation_manager.correlate(matched_rules, test_event)
        self.assertIsInstance(alerts, list)

        # Проверяем логику: если правила совпали — появились оповещения
        if matched_rules:
            self.assertGreater(len(alerts), 0)
        else:
            self.assertEqual(len(alerts), 0)

if __name__ == '__main__':
    unittest.main()
