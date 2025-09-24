"""
llmops.tuning.datasets.schemas

Pydantic-схемы для строгой валидации формата и содержания
входных данных датасетов, применяемых в процессе обучения.
"""

from typing import Optional, List, Union
from pydantic import BaseModel, validator, root_validator


class DatasetExample(BaseModel):
    """
    Схема одного примера из датасета.
    Поля:
    - input: текстовый вход модели (строка или список строк)
    - output: ожидаемый ответ модели (строка или список строк)
    - metadata: опциональные дополнительные данные (словарь)
    """
    input: Union[str, List[str]]
    output: Union[str, List[str]]
    metadata: Optional[dict] = None

    @validator('input', 'output')
    def not_empty(cls, v):
        if isinstance(v, str):
            if not v.strip():
                raise ValueError("Поле не должно быть пустым")
        elif isinstance(v, list):
            if not v or any(not isinstance(i, str) or not i.strip() for i in v):
                raise ValueError("Список должен содержать непустые строки")
        else:
            raise TypeError("Поле должно быть строкой или списком строк")
        return v


class DatasetConfig(BaseModel):
    """
    Общая конфигурация датасета.
    - name: имя датасета
    - description: краткое описание
    - examples: список примеров DatasetExample
    - version: версия датасета
    """
    name: str
    description: Optional[str]
    examples: List[DatasetExample]
    version: Optional[str] = "1.0"

    @root_validator
    def check_examples_not_empty(cls, values):
        examples = values.get('examples')
        if not examples or len(examples) == 0:
            raise ValueError("Датасет должен содержать хотя бы один пример")
        return values


if __name__ == "__main__":
    # Пример валидации
    try:
        example = DatasetExample(input="Привет", output="Hello")
        dataset = DatasetConfig(
            name="Test Dataset",
            description="Пример датасета для теста",
            examples=[example]
        )
        print("Валидация прошла успешно")
    except Exception as e:
        print(f"Ошибка валидации: {e}")
