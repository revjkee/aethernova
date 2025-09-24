# mlops/tuning/checkpoint_manager.py

import os
import json
import torch
import shutil
import logging
from typing import Any, Dict, Optional
from datetime import datetime

logger = logging.getLogger("CheckpointManager")
logger.setLevel(logging.INFO)

class CheckpointManager:
    """
    Промышленный менеджер контрольных точек.
    Совместим с PyTorch, HuggingFace, Keras. Поддерживает версионирование, авто-очистку, журналирование.
    """
    
    def __init__(
        self,
        directory: str,
        max_checkpoints: int = 5,
        metadata_filename: str = "checkpoints_meta.json"
    ):
        self.directory = directory
        self.max_checkpoints = max_checkpoints
        self.metadata_path = os.path.join(directory, metadata_filename)
        os.makedirs(self.directory, exist_ok=True)
        self._metadata = self._load_metadata()

    def _load_metadata(self) -> Dict[str, Any]:
        if os.path.exists(self.metadata_path):
            try:
                with open(self.metadata_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Ошибка загрузки метаданных: {e}")
        return {"checkpoints": []}

    def _save_metadata(self):
        try:
            with open(self.metadata_path, 'w') as f:
                json.dump(self._metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Ошибка сохранения метаданных: {e}")

    def save_checkpoint(
        self,
        state: Dict[str, Any],
        name: Optional[str] = None,
        step: Optional[int] = None,
        score: Optional[float] = None
    ) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        tag = name or f"checkpoint-{timestamp}"
        if step:
            tag += f"-step{step}"
        if score is not None:
            tag += f"-score{score:.4f}"

        path = os.path.join(self.directory, f"{tag}.pt")
        try:
            torch.save(state, path)
        except Exception as e:
            logger.error(f"Ошибка сохранения чекпоинта: {e}")
            raise

        logger.info(f"Сохранён чекпоинт: {path}")
        self._metadata["checkpoints"].append({
            "name": tag,
            "path": path,
            "timestamp": timestamp,
            "step": step,
            "score": score
        })
        self._prune_checkpoints()
        self._save_metadata()
        return path

    def load_checkpoint(self, name: str) -> Dict[str, Any]:
        path = os.path.join(self.directory, name)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Чекпоинт не найден: {path}")
        try:
            checkpoint = torch.load(path, map_location='cpu')
            logger.info(f"Загружен чекпоинт: {path}")
            return checkpoint
        except Exception as e:
            logger.error(f"Ошибка загрузки чекпоинта {path}: {e}")
            raise

    def get_latest(self) -> Optional[Dict[str, Any]]:
        if not self._metadata["checkpoints"]:
            return None
        last_entry = self._metadata["checkpoints"][-1]
        return self.load_checkpoint(os.path.basename(last_entry["path"]))

    def _prune_checkpoints(self):
        if len(self._metadata["checkpoints"]) <= self.max_checkpoints:
            return
        excess = len(self._metadata["checkpoints"]) - self.max_checkpoints
        to_delete = self._metadata["checkpoints"][:excess]
        for entry in to_delete:
            try:
                if os.path.exists(entry["path"]):
                    os.remove(entry["path"])
                    logger.info(f"Удалён старый чекпоинт: {entry['path']}")
            except Exception as e:
                logger.warning(f"Не удалось удалить чекпоинт {entry['path']}: {e}")
        self._metadata["checkpoints"] = self._metadata["checkpoints"][excess:]

    def clear_all(self):
        """
        Полная очистка всех чекпоинтов и метаданных.
        """
        shutil.rmtree(self.directory, ignore_errors=True)
        os.makedirs(self.directory, exist_ok=True)
        self._metadata = {"checkpoints": []}
        self._save_metadata()
        logger.info("Очищены все чекпоинты и метаданные.")

