# Анализ безопасности перед деплоем
# pre_deploy_check.py
# Модуль анализа безопасности перед деплоем в CI/CD пайплайне

import os
import subprocess
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)

class PreDeploySecurityCheck:
    """
    Анализ безопасности перед деплоем:
    - Статический анализ кода (bandit, flake8)
    - Проверка наличия секретов (truffleHog, git-secrets)
    - Проверка зависимостей (safety, pip-audit)
    - Проверка форматирования и стандартов
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        if not os.path.isdir(repo_path):
            raise ValueError(f"Путь {repo_path} не существует или не является директорией")

    def run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        try:
            process = subprocess.run(cmd, cwd=self.repo_path, capture_output=True, text=True, timeout=120)
            return process.returncode, process.stdout, process.stderr
        except Exception as e:
            logger.error(f"Ошибка выполнения команды {' '.join(cmd)}: {e}")
            return -1, "", str(e)

    def check_bandit(self) -> bool:
        code, out, err = self.run_command(['bandit', '-r', '.'])
        if code != 0:
            logger.error(f"Bandit failed: {err}")
            return False
        if "No issues identified." in out:
            logger.info("Bandit: проблем не найдено")
            return True
        logger.warning("Bandit: найдены проблемы")
        logger.debug(out)
        return False

    def check_flake8(self) -> bool:
        code, out, err = self.run_command(['flake8', '.'])
        if code != 0 and out:
            logger.warning("flake8: найдены ошибки стиля кода")
            logger.debug(out)
            return False
        logger.info("flake8: ошибок стиля кода не найдено")
        return True

    def check_secrets(self) -> bool:
        # Пример с git-secrets
        code, out, err = self.run_command(['git-secrets', '--scan'])
        if code != 0:
            logger.warning("git-secrets: найдены секреты в коде")
            logger.debug(out)
            return False
        logger.info("git-secrets: секретов не найдено")
        return True

    def check_dependencies(self) -> bool:
        # Пример с safety
        code, out, err = self.run_command(['safety', 'check', '--full-report'])
        if code != 0:
            logger.warning("safety: найдены уязвимости в зависимостях")
            logger.debug(out)
            return False
        logger.info("safety: уязвимостей в зависимостях не найдено")
        return True

    def run_all_checks(self) -> bool:
        logger.info("Запуск всех проверок безопасности перед деплоем")

        results = {
            "bandit": self.check_bandit(),
            "flake8": self.check_flake8(),
            "secrets": self.check_secrets(),
            "dependencies": self.check_dependencies()
        }

        all_passed = all(results.values())
        if all_passed:
            logger.info("Все проверки безопасности пройдены успешно")
        else:
            failed = [k for k, v in results.items() if not v]
            logger.error(f"Проверки не пройдены: {failed}")
        return all_passed


# Возможное использование:
# checker = PreDeploySecurityCheck('/path/to/repo')
# success = checker.run_all_checks()
# if not success:
#     raise RuntimeError("Безопасность перед деплоем не пройдена")
