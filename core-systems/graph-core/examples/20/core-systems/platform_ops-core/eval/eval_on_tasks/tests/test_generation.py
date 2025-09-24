# llmops/eval/eval_on_tasks/tests/test_generation.py

import unittest
from llmops.eval.eval_on_tasks.generation import GenerationEvaluator


class TestGenerationEvaluator(unittest.TestCase):
    def setUp(self):
        self.evaluator = GenerationEvaluator()

    def test_bleu_score_perfect(self):
        predictions = ["The quick brown fox jumps over the lazy dog"]
        references = [["The quick brown fox jumps over the lazy dog"]]
        bleu = self.evaluator.bleu_score(predictions, references)
        self.assertEqual(bleu, 1.0)

    def test_bleu_score_partial(self):
        predictions = ["The quick brown fox"]
        references = [["The quick brown fox jumps over the lazy dog"]]
        bleu = self.evaluator.bleu_score(predictions, references)
        self.assertTrue(0.0 < bleu < 1.0)

    def test_rouge_l_score(self):
        predictions = ["The quick brown fox"]
        references = [["The quick brown fox jumps over the lazy dog"]]
        rouge_l = self.evaluator.rouge_l_score(predictions, references)
        self.assertTrue(0.0 <= rouge_l <= 1.0)

    def test_meteor_score(self):
        predictions = ["A quick brown fox"]
        references = [["The quick brown fox jumps over the lazy dog"]]
        meteor = self.evaluator.meteor_score(predictions, references)
        self.assertTrue(0.0 <= meteor <= 1.0)

    def test_length_penalty(self):
        prediction = "Short text"
        reference = ["A much longer reference text for evaluation"]
        penalty = self.evaluator.length_penalty(prediction, reference)
        self.assertTrue(0.0 <= penalty <= 1.0)


if __name__ == "__main__":
    unittest.main()
