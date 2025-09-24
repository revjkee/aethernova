# intel-core/correlation-engine/tests/unit/test_rule_parsing.py

import unittest
from correlation_engine.rules.custom_rules import parse_rule

class TestRuleParsing(unittest.TestCase):
    def test_parse_simple_rule(self):
        rule_text = """
        rule:
          id: test_rule_1
          description: "Простое правило для теста"
          conditions:
            - field: src_ip
              operator: equals
              value: "192.168.1.1"
          actions:
            - alert
        """
        rule = parse_rule(rule_text)
        self.assertIsNotNone(rule)
        self.assertEqual(rule['id'], 'test_rule_1')
        self.assertIn('conditions', rule)
        self.assertEqual(len(rule['conditions']), 1)
        self.assertEqual(rule['conditions'][0]['field'], 'src_ip')
        self.assertEqual(rule['conditions'][0]['operator'], 'equals')
        self.assertEqual(rule['conditions'][0]['value'], '192.168.1.1')

    def test_parse_rule_missing_fields(self):
        rule_text = """
        rule:
          id: incomplete_rule
          description: "Правило с пропущенными условиями"
        """
        with self.assertRaises(ValueError):
            parse_rule(rule_text)

    def test_parse_rule_invalid_format(self):
        invalid_rule_text = "это не yaml"
        with self.assertRaises(Exception):
            parse_rule(invalid_rule_text)

if __name__ == '__main__':
    unittest.main()
