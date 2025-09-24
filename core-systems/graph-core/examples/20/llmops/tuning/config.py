from typing import List, Optional, Literal, Dict, Union
from pydantic import BaseModel, Field, validator
import os

class TokenizerConfig(BaseModel):
    name_or_path: str = Field(..., description="Путь или имя предобученного токенизатора")
    use_fast: bool = Field(default=True, description="Использовать быстрый токенизатор HuggingFace")
    padding_side: Optional[Literal["left", "right"]] = Field(default="right")
    truncation_side: Optional[Literal["left", "right"]] = Field(default="right")

class ModelConfig(BaseModel):
    name_or_path: str = Field(..., description="Путь или имя модели")
    trust_remote_code: bool = Field(default=True)
    use_flash_attention: Optional[bool] = Field(default=True)
    quantization: Optional[Literal["8bit", "4bit", None]] = Field(default=None)
    gradient_checkpointing: bool = Field(default=True)
    lora_r: Optional[int] = Field(default=None)
    lora_alpha: Optional[int] = Field(default=None)
    lora_dropout: Optional[float] = Field(default=0.05)

class OptimizerConfig(BaseModel):
    learning_rate: float = Field(..., ge=1e-7, le=1e-1)
    weight_decay: float = Field(default=0.01)
    betas: Optional[List[float]] = Field(default=[0.9, 0.999])
    epsilon: float = Field(default=1e-8)
    warmup_steps: int = Field(default=100)
    lr_scheduler_type: Literal["linear", "cosine", "polynomial"] = "cosine"

class TrainingConfig(BaseModel):
    output_dir: str = Field(..., description="Директория для чекпоинтов и логов")
    logging_dir: str = Field(default="logs")
    per_device_train_batch_size: int = Field(default=4)
    per_device_eval_batch_size: int = Field(default=4)
    gradient_accumulation_steps: int = Field(default=1)
    num_train_epochs: float = Field(default=3.0)
    max_steps: Optional[int] = Field(default=None)
    eval_steps: int = Field(default=100)
    save_steps: int = Field(default=500)
    logging_steps: int = Field(default=50)
    save_total_limit: int = Field(default=3)
    bf16: bool = Field(default=True)
    fp16: bool = Field(default=False)
    tf32: bool = Field(default=True)
    dataloader_num_workers: int = Field(default=4)

class StrategyConfig(BaseModel):
    type: Literal["sft", "ppo", "dpo", "orpo"] = "sft"
    use_rlhf_adapters: bool = Field(default=False)

class DatasetConfig(BaseModel):
    train_path: str = Field(..., description="Путь к тренировочному датасету")
    eval_path: Optional[str] = Field(default=None)
    format: Literal["json", "csv", "parquet"] = "json"
    max_length: int = Field(default=2048)
    streaming: bool = Field(default=False)

class TuningConfig(BaseModel):
    seed: int = Field(default=42)
    tokenizer: TokenizerConfig
    model: ModelConfig
    optimizer: OptimizerConfig
    training: TrainingConfig
    strategy: StrategyConfig
    dataset: DatasetConfig
    additional_args: Optional[Dict[str, Union[str, int, float, bool]]] = Field(default_factory=dict)

    @validator("output_dir", pre=True, always=True)
    def validate_output_dir(cls, v):
        os.makedirs(v, exist_ok=True)
        return v

# Экземпляр-конфиг можно загружать из JSON/YAML/ENV в стороннем loader.py
