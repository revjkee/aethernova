import logging
from typing import List, Dict, Any, Optional

from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
from rouge_score import rouge_scorer
from bert_score import score as bert_score
from evaluate import load as hf_load

from llmops.eval.utils import timed_block, sanitize_text

log = logging.getLogger("quality_metrics")


class MetricEvaluator:
    def __init__(self, use_bertscore: bool = True, use_meteor: bool = True):
        self.rouge = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)
        self.bleu_smooth = SmoothingFunction().method1
        self.use_bertscore = use_bertscore
        self.use_meteor = use_meteor
        self.meteor = hf_load("meteor") if use_meteor else None

    def evaluate(self, predictions: List[str], references: List[str]) -> Dict[str, Any]:
        """
        Оценка качества генерации модели по множеству метрик:
        - BLEU
        - ROUGE-L
        - METEOR
        - BERTScore
        """
        metrics = {
            "bleu": [],
            "rougeL": [],
            "meteor": [],
        }
        preds, refs = self._sanitize(predictions, references)

        with timed_block("Evaluating BLEU & ROUGE"):
            for hyp, ref in zip(preds, refs):
                bleu = sentence_bleu([ref.split()], hyp.split(), smoothing_function=self.bleu_smooth)
                rouge = self.rouge.score(ref, hyp)['rougeL'].fmeasure
                metrics["bleu"].append(bleu)
                metrics["rougeL"].append(rouge)

        if self.use_meteor:
            with timed_block("Evaluating METEOR"):
                meteor_scores = self.meteor.compute(predictions=preds, references=refs)['meteor']
                metrics["meteor"] = meteor_scores if isinstance(meteor_scores, list) else [meteor_scores] * len(preds)

        if self.use_bertscore:
            with timed_block("Evaluating BERTScore"):
                P, R, F1 = bert_score(preds, refs, lang="en", rescale_with_baseline=True)
                metrics["bertscore_precision"] = P.tolist()
                metrics["bertscore_recall"] = R.tolist()
                metrics["bertscore_f1"] = F1.tolist()

        return self._aggregate(metrics)

    def _sanitize(self, preds: List[str], refs: List[str]) -> (List[str], List[str]):
        sanitized_preds = [sanitize_text(p) for p in preds]
        sanitized_refs = [sanitize_text(r) for r in refs]
        return sanitized_preds, sanitized_refs

    def _aggregate(self, scores: Dict[str, List[float]]) -> Dict[str, float]:
        aggregated = {}
        for key, values in scores.items():
            if values:
                aggregated[f"{key}_avg"] = round(float(sum(values) / len(values)), 4)
        return aggregated


def compute_quality_metrics(predictions: List[str], references: List[str], config: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    config = config or {}
    evaluator = MetricEvaluator(
        use_bertscore=config.get("use_bertscore", True),
        use_meteor=config.get("use_meteor", True),
    )
    return evaluator.evaluate(predictions, references)
