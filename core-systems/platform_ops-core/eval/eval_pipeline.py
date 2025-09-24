# llmops/eval/eval_pipeline.py

from typing import List, Dict, Any
from llmops.eval.eval_on_tasks.classification import ClassificationEvaluator
from llmops.eval.eval_on_tasks.generation import GenerationEvaluator
from llmops.eval.eval_on_tasks.retrieval import RetrievalEvaluator
from llmops.eval.eval_on_tasks.hallucination_checker import HallucinationChecker
from llmops.eval.eval_on_tasks.toxicity_detector import ToxicityDetector


class EvalPipeline:
    """
    Автоматизация оценки качества моделей LLM по различным задачам.
    Объединяет классификацию, генерацию, поиск, проверку галлюцинаций и токсичности.
    """

    def __init__(self):
        self.classification_evaluator = ClassificationEvaluator()
        self.generation_evaluator = GenerationEvaluator()
        self.retrieval_evaluator = RetrievalEvaluator()
        self.hallucination_checker = HallucinationChecker()
        self.toxicity_detector = ToxicityDetector()

    def evaluate_classification(self, predictions: List, references: List) -> Dict[str, float]:
        """
        Оценка классификационных задач с несколькими метриками.
        """
        metrics = self.classification_evaluator.evaluate(predictions, references)
        return metrics

    def evaluate_generation(self, predictions: List[str], references: List[str]) -> Dict[str, float]:
        """
        Оценка генеративных задач (текст).
        """
        metrics = self.generation_evaluator.evaluate(predictions, references)
        return metrics

    def evaluate_retrieval(self, predictions: List[List[str]], references: List[List[str]]) -> Dict[str, float]:
        """
        Оценка задач поиска и выборки.
        """
        metrics = self.retrieval_evaluator.evaluate(predictions, references)
        return metrics

    def check_hallucination(self, predictions: List[str], references: List[str]) -> Dict[str, Any]:
        """
        Проверка наличия галлюцинаций в ответах моделей.
        """
        results = self.hallucination_checker.check(predictions, references)
        return results

    def detect_toxicity(self, texts: List[str]) -> Dict[str, Any]:
        """
        Определение токсичности в сгенерированных текстах.
        """
        results = self.toxicity_detector.detect(texts)
        return results

    def full_evaluation(self, task_type: str, predictions: List, references: List) -> Dict[str, Any]:
        """
        Универсальный метод для запуска оценки по типу задачи.
        """
        if task_type == "classification":
            return self.evaluate_classification(predictions, references)
        elif task_type == "generation":
            return self.evaluate_generation(predictions, references)
        elif task_type == "retrieval":
            return self.evaluate_retrieval(predictions, references)
        else:
            raise ValueError(f"Unsupported task type: {task_type}")


# Конец файла
