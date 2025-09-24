import re
from typing import Any, Dict, List, Optional, Union
from ..utils import logger

class FormatValidationError(Exception):
    """Ошибка формата при валидации вывода или ввода модели."""


class FormatValidator:
    """
    Валидатор структуры входных и выходных данных для задач
    summarization, qa, reasoning и других.
    """

    def __init__(self):
        self.required_fields = {
            "summarization": ["context", "summary"],
            "qa": ["question", "context", "answer"],
            "reasoning": ["input", "steps", "final_answer"]
        }

    def validate_input(self, task_type: str, sample: Dict[str, Any]) -> None:
        logger.debug(f"Validating input format for task: {task_type}")
        if task_type not in self.required_fields:
            raise FormatValidationError(f"Unknown task type: {task_type}")

        required = self.required_fields[task_type]
        for field in required:
            if field not in sample:
                raise FormatValidationError(
                    f"Missing required field '{field}' in input for task '{task_type}'"
                )
            if not isinstance(sample[field], str):
                raise FormatValidationError(
                    f"Field '{field}' must be of type str in task '{task_type}'"
                )

    def validate_output(
        self,
        task_type: str,
        output: Union[str, Dict[str, Any]]
    ) -> None:
        logger.debug(f"Validating output for task: {task_type}")
        if task_type == "summarization":
            self._validate_summary(output)
        elif task_type == "qa":
            self._validate_answer(output)
        elif task_type == "reasoning":
            self._validate_reasoning_chain(output)
        else:
            raise FormatValidationError(f"Unknown task type: {task_type}")

    def _validate_summary(self, output: Any) -> None:
        if not isinstance(output, str):
            raise FormatValidationError("Output summary must be a string.")
        if len(output.strip()) == 0:
            raise FormatValidationError("Output summary is empty.")
        if len(output.split()) < 3:
            logger.warning("Suspiciously short summary.")

    def _validate_answer(self, output: Any) -> None:
        if not isinstance(output, str):
            raise FormatValidationError("Answer must be a string.")
        if output.lower().strip() in ["", "n/a", "unknown"]:
            logger.warning("Empty or generic answer detected.")

    def _validate_reasoning_chain(self, output: Any) -> None:
        if not isinstance(output, dict):
            raise FormatValidationError("Reasoning output must be a dict.")
        required_keys = ["steps", "final_answer"]
        for key in required_keys:
            if key not in output:
                raise FormatValidationError(f"Missing key '{key}' in reasoning output.")
        if not isinstance(output["steps"], list) or not output["steps"]:
            raise FormatValidationError("Reasoning steps must be a non-empty list.")
        if not isinstance(output["final_answer"], str):
            raise FormatValidationError("Final answer must be a string.")

    def validate_batch(
        self,
        task_type: str,
        inputs: List[Dict[str, Any]],
        outputs: List[Any]
    ) -> None:
        logger.debug("Batch validation started")
        if len(inputs) != len(outputs):
            raise FormatValidationError("Input/output length mismatch in batch.")
        for i, (inp, outp) in enumerate(zip(inputs, outputs)):
            try:
                self.validate_input(task_type, inp)
                self.validate_output(task_type, outp)
            except FormatValidationError as e:
                logger.error(f"Validation error at index {i}: {e}")
                raise
