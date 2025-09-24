# llmops/eval/eval_on_tasks/generation.py

from typing import List, Dict, Any
from .base_evaluator import BaseEvaluator
from nltk.translate.bleu_score import corpus_bleu, SmoothingFunction
from rouge_score import rouge_scorer


class GenerationEvaluator(BaseEvaluator):
    """
    Оценщик для задач генерации текста.
    Поддерживает метрики BLEU и ROUGE.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.bleu_weights = self.config.get("bleu_weights", (0.25, 0.25, 0.25, 0.25))
        self.rouge_types = self.config.get("rouge_types", ["rouge1", "rouge2", "rougeL"])

        self.rouge_scorer = rouge_scorer.RougeScorer(self.rouge_types, use_stemmer=True)
        self.smooth_fn = SmoothingFunction().method1

    def evaluate(self, predictions: List[str], references: List[List[str]]) -> Dict[str, float]:
        """
        Оценка генерации текста.
        :param predictions: список предсказанных текстов (str)
        :param references: список списков эталонных текстов (List[str])
        :return: словарь метрик
        """
        # BLEU требует токенизации
        tokenized_preds = [pred.split() for pred in predictions]
        tokenized_refs = [[ref.split() for ref in refs] for refs in references]

        bleu_score = corpus_bleu(
            tokenized_refs,
            tokenized_preds,
            weights=self.bleu_weights,
            smoothing_function=self.smooth_fn
        )

        rouge_scores_agg = {key: 0.0 for key in self.rouge_types}
        n = len(predictions)

        for pred, refs in zip(predictions, references):
            # Выбираем лучшую по rouge метрику среди всех эталонов
            rouge_max = {key: 0.0 for key in self.rouge_types}
            for ref in refs:
                scores = self.rouge_scorer.score(ref, pred)
                for key in self.rouge_types:
                    rouge_max[key] = max(rouge_max[key], scores[key].fmeasure)
            for key in self.rouge_types:
                rouge_scores_agg[key] += rouge_max[key]

        # Средние значения
        rouge_avg = {f"avg_{k}": v / n for k, v in rouge_scores_agg.items()}

        metrics = {
            "bleu": bleu_score,
            **rouge_avg,
        }
        return metrics

    def reset(self) -> None:
        """
        Для данного оценщика состояние не сохраняется, метод пустой.
        """
        pass
