# intel-core/correlation-engine/tests/unit/test_ml_models.py

import unittest
import numpy as np
from correlation_engine.ml.anomaly_detection_model import AnomalyDetectionModel

class TestAnomalyDetectionModel(unittest.TestCase):
    def setUp(self):
        self.model = AnomalyDetectionModel()

    def test_model_initialization(self):
        self.assertIsNotNone(self.model)
        self.assertFalse(self.model.is_trained)

    def test_training_with_valid_data(self):
        # Синтетические данные для обучения
        X_train = np.random.rand(100, 10)
        y_train = np.random.randint(0, 2, size=100)
        self.model.train(X_train, y_train)
        self.assertTrue(self.model.is_trained)

    def test_inference_on_trained_model(self):
        X_train = np.random.rand(100, 10)
        y_train = np.random.randint(0, 2, size=100)
        self.model.train(X_train, y_train)

        X_test = np.random.rand(10, 10)
        predictions = self.model.predict(X_test)
        self.assertEqual(len(predictions), 10)

    def test_predict_without_training_raises(self):
        X_test = np.random.rand(5, 10)
        with self.assertRaises(RuntimeError):
            self.model.predict(X_test)

if __name__ == '__main__':
    unittest.main()
