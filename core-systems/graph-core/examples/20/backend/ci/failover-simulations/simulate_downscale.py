import os
import time
import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s"
)

NAMESPACE = os.getenv("KUBE_NAMESPACE", "production")
DEPLOYMENT_NAME = os.getenv("TARGET_DEPLOYMENT", "teslaai-backend")
DOWNSCALE_REPLICAS = int(os.getenv("DOWNSCALE_TO", 1))
UPSCALE_REPLICAS = int(os.getenv("UPSCALE_TO", 3))
DURATION = int(os.getenv("DOWNSCALE_DURATION", 60))  # в секундах

def load_kube_config():
    try:
        config.load_incluster_config()
        logging.info("Загружена конфигурация из пода (in-cluster)")
    except config.config_exception.ConfigException:
        config.load_kube_config()
        logging.info("Загружена локальная kubeconfig")

def scale_deployment(api, replicas):
    try:
        body = {
            "spec": {
                "replicas": replicas
            }
        }
        logging.info(f"Изменение реплик '{DEPLOYMENT_NAME}' в '{NAMESPACE}' на {replicas}")
        api.patch_namespaced_deployment_scale(
            name=DEPLOYMENT_NAME,
            namespace=NAMESPACE,
            body=body
        )
        logging.info("Операция масштабирования завершена успешно.")
    except ApiException as e:
        logging.error(f"Ошибка масштабирования: {e}")

def simulate_downscale():
    load_kube_config()
    api = client.AppsV1Api()

    logging.info("=== Старт симуляции даунскейла ===")
    scale_deployment(api, DOWNSCALE_REPLICAS)

    logging.info(f"Ожидание {DURATION} секунд (работа в режиме с пониженными репликами)...")
    time.sleep(DURATION)

    logging.info("=== Восстановление из симуляции ===")
    scale_deployment(api, UPSCALE_REPLICAS)

if __name__ == "__main__":
    try:
        simulate_downscale()
        logging.info("Симуляция завершена успешно.")
    except Exception as e:
        logging.exception(f"Фатальная ошибка: {e}")
        exit(1)
