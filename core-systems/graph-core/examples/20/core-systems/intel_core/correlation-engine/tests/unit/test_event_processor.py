# intel-core/correlation-engine/tests/unit/test_event_processor.py

import unittest
from correlation_engine.engines.event_processor import EventProcessor

class TestEventProcessor(unittest.TestCase):
    def setUp(self):
        self.processor = EventProcessor()

    def test_process_single_event(self):
        event = {
            'id': 'evt1',
            'type': 'login',
            'source_ip': '192.168.1.100',
            'user': 'admin'
        }
        result = self.processor.process_event(event)
        self.assertIsNotNone(result)
        self.assertEqual(result.get('id'), 'evt1')
        self.assertEqual(result.get('type'), 'login')

    def test_process_event_missing_fields(self):
        event = {
            'id': 'evt2',
            # 'type' пропущено
            'source_ip': '192.168.1.101',
            'user': 'guest'
        }
        with self.assertRaises(ValueError):
            self.processor.process_event(event)

    def test_process_multiple_events(self):
        events = [
            {'id': 'evt3', 'type': 'file_access', 'file': '/etc/passwd'},
            {'id': 'evt4', 'type': 'login', 'source_ip': '10.0.0.1'},
        ]
        results = []
        for event in events:
            results.append(self.processor.process_event(event))
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['type'], 'file_access')
        self.assertEqual(results[1]['type'], 'login')

if __name__ == '__main__':
    unittest.main()
