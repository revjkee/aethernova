# mlops/training/train_runner.py

import argparse
import logging
import yaml
import os
import time
import torch
import random
import numpy as np

from mlops.training.model_trainer import ModelTrainer
from mlops.tuning.checkpoint_manager import CheckpointManager
from mlops.metrics.evaluation import evaluate_model

# === Настройка логгера ===
logger = logging.getLogger("TrainRunner")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)

def load_config(config_path: str) -> dict:
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def main(config_path: str):
    logger.info("Запуск обучения...")

    # === Загрузка конфигурации ===
    config = load_config(config_path)
    logger.info(f"Загружена конфигурация: {config_path}")

    # === Фиксация seed ===
    if "seed" in config:
        set_seed(config["seed"])
        logger.info(f"Установлен seed: {config['seed']}")

    # === Устройство ===
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Выбранное устройство: {device}")

    # === Инициализация менеджера чекпоинтов ===
    checkpoint_dir = config.get("checkpoint_dir", "./checkpoints")
    checkpoint_manager = CheckpointManager(directory=checkpoint_dir)

    # === Инициализация тренера ===
    trainer = ModelTrainer(config=config, device=device, checkpoint_manager=checkpoint_manager)

    # === Обучение ===
    start_time = time.time()
    trainer.train()
    logger.info("Обучение завершено.")

    # === Оценка ===
    if config.get("evaluate_after_training", True):
        results = evaluate_model(trainer.model, trainer.val_loader, device=device)
        logger.info(f"Оценка модели: {results}")

    logger.info(f"Общее время обучения: {(time.time() - start_time):.2f} сек.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TeslaAI MLOps Train Runner")
    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="Путь к YAML конфигурации обучения (training_config.yaml)"
    )
    args = parser.parse_args()
    main(args.config)
