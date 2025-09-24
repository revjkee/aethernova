# llmops/eval/eval_on_tasks/tests/test_classification.py

import unittest
from llmops.eval.eval_on_tasks.classification import ClassificationEvaluator


class TestClassificationEvaluator(unittest.TestCase):
    def setUp(self):
        self.evaluator = ClassificationEvaluator()

    def test_accuracy_empty(self):
        predictions = []
        references = []
        accuracy = self.evaluator.accuracy(predictions, references)
        self.assertEqual(accuracy, 0.0)

    def test_accuracy_perfect(self):
        predictions = [1, 0, 1, 1]
        references = [1, 0, 1, 1]
        accuracy = self.evaluator.accuracy(predictions, references)
        self.assertEqual(accuracy, 1.0)

    def test_accuracy_partial(self):
        predictions = [1, 0, 0, 1]
        references = [1, 1, 0, 1]
        accuracy = self.evaluator.accuracy(predictions, references)
        self.assertAlmostEqual(accuracy, 0.75)

    def test_f1_score(self):
        predictions = [1, 0, 1, 1]
        references = [1, 0, 0, 1]
        f1 = self.evaluator.f1_score(predictions, references)
        # Проверка что F1 находится в корректном диапазоне
        self.assertTrue(0.0 <= f1 <= 1.0)

    def test_precision_recall(self):
        predictions = [1, 1, 0, 0]
        references = [1, 0, 1, 0]
        precision = self.evaluator.precision(predictions, references)
        recall = self.evaluator.recall(predictions, references)
        self.assertTrue(0.0 <= precision <= 1.0)
        self.assertTrue(0.0 <= recall <= 1.0)


if __name__ == "__main__":
    unittest.main()
