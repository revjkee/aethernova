import ray
from typing import Any, Dict
import logging

logger = logging.getLogger(__name__)

ray.init(ignore_reinit_error=True)

@ray.remote
class RayInferenceWorker:
    def __init__(self, model):
        self.model = model
        logger.info("RayInferenceWorker инициализирован")

    def run_inference(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Выполняет инференс на переданных данных.

        :param input_data: входные данные для модели
        :return: результаты инференса
        """
        try:
            result = self.model.infer(input_data)
            logger.debug("Инференс выполнен успешно")
            return result
        except Exception as e:
            logger.error(f"Ошибка при инференсе в Ray task: {e}")
            raise

def submit_inference_task(worker_handle, input_data: Dict[str, Any]):
    """
    Отправка задачи на выполнение инференса через Ray.

    :param worker_handle: объект RayInferenceWorker
    :param input_data: входные данные
    :return: Ray future
    """
    return worker_handle.run_inference.remote(input_data)
