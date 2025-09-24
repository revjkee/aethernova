# llmops/integrations/huggingface_sync.py

"""
Модуль для синхронизации артефактов, моделей и токенизаторов с HuggingFace Hub.
Обеспечивает экспорт, обновление и загрузку данных из пространства HuggingFace (Spaces, Models, Datasets).
Используется в пайплайнах CI/CD, для контроля версий моделей, публикации и мониторинга.
"""

import os
import logging
from huggingface_hub import (
    HfApi,
    HfFolder,
    Repository,
    snapshot_download,
    create_repo,
    upload_file,
)
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# --- Настройки по умолчанию ---
HF_TOKEN_ENV = "HF_TOKEN"
DEFAULT_HF_ORG = "TeslaAI-Genesis"
DEFAULT_PRIVATE = True


class HuggingFaceSync:
    def __init__(
        self,
        token: Optional[str] = None,
        org: Optional[str] = None,
    ):
        self.token = token or os.getenv(HF_TOKEN_ENV)
        if not self.token:
            raise ValueError("HuggingFace token не найден в переменной окружения или аргументе.")

        self.api = HfApi(token=self.token)
        self.org = org or DEFAULT_HF_ORG
        logger.info(f"Инициализирован HuggingFaceSync для организации: {self.org}")

    def ensure_repo(self, repo_name: str, repo_type: str = "model", private: bool = DEFAULT_PRIVATE) -> str:
        """
        Создаёт репозиторий в HuggingFace, если он не существует.
        """
        full_repo = f"{self.org}/{repo_name}"
        try:
            self.api.create_repo(
                name=repo_name,
                token=self.token,
                organization=self.org,
                repo_type=repo_type,
                private=private,
                exist_ok=True,
            )
            logger.info(f"Репозиторий {full_repo} подтверждён или создан.")
        except Exception as e:
            logger.error(f"Ошибка при создании репозитория: {e}")
            raise

        return full_repo

    def upload_directory(
        self,
        local_dir: str,
        repo_name: str,
        repo_type: str = "model",
        commit_message: str = "Sync from llmops",
        private: bool = DEFAULT_PRIVATE,
    ):
        """
        Загружает содержимое директории в HuggingFace репозиторий.
        """
        full_repo = self.ensure_repo(repo_name, repo_type, private)
        repo_url = self.api.repo_info(full_repo, repo_type=repo_type).git_url
        repo_path = Path(f"/tmp/{repo_name}")

        if repo_path.exists():
            import shutil
            shutil.rmtree(repo_path)

        repo = Repository(
            local_dir=str(repo_path),
            clone_from=repo_url,
            token=self.token,
        )
        repo.git_pull()

        for root, _, files in os.walk(local_dir):
            for file in files:
                full_file_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_file_path, start=local_dir)
                dest_path = repo_path / rel_path
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with open(full_file_path, "rb") as src_file:
                    with open(dest_path, "wb") as dst_file:
                        dst_file.write(src_file.read())
                logger.info(f"Подготовлен файл: {rel_path}")

        repo.push_to_hub(commit_message=commit_message)
        logger.info(f"Файлы из {local_dir} синхронизированы с {full_repo}")

    def download_snapshot(
        self,
        repo_id: str,
        repo_type: str = "model",
        local_dir: Optional[str] = None,
    ) -> str:
        """
        Загружает снапшот репозитория HuggingFace.
        """
        target_path = snapshot_download(
            repo_id=repo_id,
            repo_type=repo_type,
            token=self.token,
            local_dir=local_dir,
        )
        logger.info(f"Загружен снапшот {repo_id} в {target_path}")
        return target_path
