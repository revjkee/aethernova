from pydantic import BaseModel, Field, validator, ValidationError
from typing import List, Optional, Union, Dict
from enum import Enum
from ..utils import logger


# --- ENUM'ы для формализации допустимых значений ---

class TaskType(str, Enum):
    summarization = "summarization"
    qa = "qa"
    reasoning = "reasoning"


# --- SCHEMAS FOR INPUTS ---

class SummarizationInput(BaseModel):
    context: str = Field(..., min_length=10, description="Контекст для суммаризации")
    summary: Optional[str]

class QAInput(BaseModel):
    question: str = Field(..., min_length=3)
    context: str = Field(..., min_length=10)
    answer: Optional[str]

class ReasoningInput(BaseModel):
    input: str = Field(..., min_length=5)
    steps: Optional[List[str]]
    final_answer: Optional[str]


# --- SCHEMAS FOR OUTPUTS ---

class SummarizationOutput(BaseModel):
    summary: str = Field(..., min_length=3)

class QAOutput(BaseModel):
    answer: str = Field(..., min_length=1)

class ReasoningOutput(BaseModel):
    steps: List[str] = Field(..., min_items=1)
    final_answer: str = Field(..., min_length=1)

    @validator("steps", each_item=True)
    def step_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Пустой reasoning step")
        return v


# --- WRAPPER ДЛЯ УНИВЕРСАЛЬНОЙ ВАЛИДАЦИИ ---

class SchemaValidator:
    def __init__(self):
        self.task_input_schemas = {
            TaskType.summarization: SummarizationInput,
            TaskType.qa: QAInput,
            TaskType.reasoning: ReasoningInput,
        }
        self.task_output_schemas = {
            TaskType.summarization: SummarizationOutput,
            TaskType.qa: QAOutput,
            TaskType.reasoning: ReasoningOutput,
        }

    def validate_input(self, task_type: Union[str, TaskType], data: Dict) -> None:
        logger.debug(f"Validating input for task: {task_type}")
        task_enum = TaskType(task_type)
        model = self.task_input_schemas[task_enum]
        try:
            model(**data)
        except ValidationError as e:
            logger.error(f"Input validation failed: {e}")
            raise

    def validate_output(self, task_type: Union[str, TaskType], data: Dict) -> None:
        logger.debug(f"Validating output for task: {task_type}")
        task_enum = TaskType(task_type)
        model = self.task_output_schemas[task_enum]
        try:
            model(**data)
        except ValidationError as e:
            logger.error(f"Output validation failed: {e}")
            raise

    def validate_pair(self, task_type: Union[str, TaskType], input_data: Dict, output_data: Dict) -> None:
        logger.debug(f"Validating input-output pair for task: {task_type}")
        self.validate_input(task_type, input_data)
        self.validate_output(task_type, output_data)

    def validate_batch(
        self,
        task_type: Union[str, TaskType],
        inputs: List[Dict],
        outputs: List[Dict],
    ) -> None:
        logger.debug(f"Batch schema validation started for task: {task_type}")
        if len(inputs) != len(outputs):
            raise ValueError("Mismatch in input/output batch size.")
        for i, (inp, outp) in enumerate(zip(inputs, outputs)):
            try:
                self.validate_pair(task_type, inp, outp)
            except Exception as e:
                logger.error(f"Schema validation failed at index {i}: {e}")
                raise
