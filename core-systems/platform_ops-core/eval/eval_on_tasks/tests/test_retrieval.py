# llmops/eval/eval_on_tasks/tests/test_retrieval.py

import unittest
from llmops.eval.eval_on_tasks.retrieval import RetrievalEvaluator


class TestRetrievalEvaluator(unittest.TestCase):
    def setUp(self):
        self.evaluator = RetrievalEvaluator()

    def test_precision_at_k_perfect(self):
        predictions = [["doc1", "doc2", "doc3"]]
        references = [["doc1", "doc2", "doc3"]]
        precision = self.evaluator.precision_at_k(predictions, references, k=3)
        self.assertEqual(precision, 1.0)

    def test_precision_at_k_partial(self):
        predictions = [["doc1", "doc4", "doc5"]]
        references = [["doc1", "doc2", "doc3"]]
        precision = self.evaluator.precision_at_k(predictions, references, k=3)
        self.assertAlmostEqual(precision, 1/3)

    def test_recall_at_k(self):
        predictions = [["doc1", "doc2"]]
        references = [["doc1", "doc2", "doc3"]]
        recall = self.evaluator.recall_at_k(predictions, references, k=2)
        self.assertAlmostEqual(recall, 2/3)

    def test_mean_average_precision(self):
        predictions = [["doc1", "doc2", "doc3"]]
        references = [["doc1", "doc2"]]
        map_score = self.evaluator.mean_average_precision(predictions, references)
        self.assertTrue(0.0 <= map_score <= 1.0)

    def test_ndcg(self):
        predictions = [["doc1", "doc2", "doc3"]]
        references = [["doc3", "doc2", "doc1"]]
        ndcg_score = self.evaluator.ndcg(predictions, references, k=3)
        self.assertTrue(0.0 <= ndcg_score <= 1.0)


if __name__ == "__main__":
    unittest.main()
