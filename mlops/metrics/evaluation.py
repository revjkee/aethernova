# mlops/metrics/evaluation.py

import torch
import logging
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    mean_squared_error,
    mean_absolute_error,
    r2_score
)
from typing import Any, Dict, List, Union

try:
    from nltk.translate.bleu_score import sentence_bleu
    nltk_installed = True
except ImportError:
    nltk_installed = False

logger = logging.getLogger("ModelEvaluator")
logger.setLevel(logging.INFO)

def evaluate_model(
    model: torch.nn.Module,
    dataloader: torch.utils.data.DataLoader,
    device: Union[str, torch.device] = "cpu",
    task: str = "auto"
) -> Dict[str, float]:
    """
    Промышленная оценка модели.

    task:
      - "auto" — определить автоматически
      - "classification"
      - "regression"
      - "nlp-generation"
    """
    model.eval()
    model.to(device)
    y_true, y_pred = [], []

    with torch.no_grad():
        for batch in dataloader:
            inputs, labels = batch
            inputs, labels = inputs.to(device), labels.to(device)

            outputs = model(inputs)
            if task in ["auto", "classification"]:
                if outputs.shape[-1] > 1:
                    preds = torch.argmax(outputs, dim=1)
                else:
                    preds = (outputs > 0.5).int().view(-1)
                y_pred.extend(preds.cpu().tolist())
                y_true.extend(labels.cpu().tolist())
            elif task == "regression":
                y_pred.extend(outputs.view(-1).cpu().tolist())
                y_true.extend(labels.view(-1).cpu().tolist())
            elif task == "nlp-generation":
                if not nltk_installed:
                    raise ImportError("nltk required for BLEU evaluation")
                y_pred.extend([output.tolist() for output in outputs])
                y_true.extend([label.tolist() for label in labels])
            else:
                raise ValueError(f"Неизвестный тип задачи: {task}")

    # === Метрики ===
    metrics = {}
    if task in ["auto", "classification"]:
        metrics["accuracy"] = accuracy_score(y_true, y_pred)
        metrics["f1_score"] = f1_score(y_true, y_pred, average="macro")
        metrics["precision"] = precision_score(y_true, y_pred, average="macro")
        metrics["recall"] = recall_score(y_true, y_pred, average="macro")
    elif task == "regression":
        metrics["mse"] = mean_squared_error(y_true, y_pred)
        metrics["mae"] = mean_absolute_error(y_true, y_pred)
        metrics["r2"] = r2_score(y_true, y_pred)
    elif task == "nlp-generation":
        if nltk_installed:
            # BLEU рассчитывается по парно для простоты
            scores = [
                sentence_bleu([ref], hyp)
                for ref, hyp in zip(y_true, y_pred)
            ]
            metrics["bleu"] = sum(scores) / len(scores)
        else:
            metrics["bleu"] = -1.0

    logger.info(f"[Evaluation] Метрики: {metrics}")
    return metrics
