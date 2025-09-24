import onnxruntime as ort
import numpy as np
from typing import Any, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class ONNXInference:
    def __init__(self, model_path: str, providers: Optional[list] = None):
        """
        Инициализация сессии ONNX Runtime.
        
        :param model_path: путь к .onnx модели
        :param providers: список провайдеров исполнения (например, ['CPUExecutionProvider', 'CUDAExecutionProvider'])
        """
        self.model_path = model_path
        self.providers = providers or ['CPUExecutionProvider']

        try:
            self.session = ort.InferenceSession(self.model_path, providers=self.providers)
            logger.info(f"ONNX модель загружена: {model_path} с провайдерами {self.providers}")
        except Exception as e:
            logger.error(f"Ошибка загрузки модели ONNX: {e}")
            raise

    def infer(self, input_feed: Dict[str, Any]) -> Dict[str, np.ndarray]:
        """
        Запуск инференса модели с заданным входом.

        :param input_feed: словарь {имя_входа: данные}
        :return: словарь выходных данных {имя_выхода: numpy.ndarray}
        """
        try:
            outputs = self.session.run(None, input_feed)
            output_names = [output.name for output in self.session.get_outputs()]
            result = dict(zip(output_names, outputs))
            logger.debug(f"Инференс выполнен успешно: выходы {list(result.keys())}")
            return result
        except Exception as e:
            logger.error(f"Ошибка при инференсе ONNX: {e}")
            raise
