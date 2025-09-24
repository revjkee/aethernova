# intel-core/correlation-engine/tests/unit/test_utils.py

import unittest
from correlation_engine.engines.utils import normalize_event, extract_timestamp, validate_rule_format

class TestUtils(unittest.TestCase):

    def test_normalize_event(self):
        raw_event = {
            'timestamp': '2025-07-18T12:34:56Z',
            'event_type': 'login',
            'user': 'test_user',
            'details': {}
        }
        normalized = normalize_event(raw_event)
        self.assertIn('timestamp', normalized)
        self.assertIn('event_type', normalized)
        self.assertEqual(normalized['event_type'], 'login')

    def test_extract_timestamp_valid(self):
        event = {'timestamp': '2025-07-18T12:34:56Z'}
        ts = extract_timestamp(event)
        self.assertEqual(ts, '2025-07-18T12:34:56Z')

    def test_extract_timestamp_missing(self):
        event = {}
        ts = extract_timestamp(event)
        self.assertIsNone(ts)

    def test_validate_rule_format_valid(self):
        rule = {
            'id': 'rule_1',
            'conditions': ['event_type == "login"'],
            'actions': ['alert']
        }
        valid = validate_rule_format(rule)
        self.assertTrue(valid)

    def test_validate_rule_format_invalid(self):
        rule = {
            'id': 'rule_2',
            'conditions': None,
            'actions': []
        }
        valid = validate_rule_format(rule)
        self.assertFalse(valid)

if __name__ == '__main__':
    unittest.main()
