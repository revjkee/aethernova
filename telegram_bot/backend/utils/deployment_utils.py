import subprocess
import logging
from typing import Optional

logger = logging.getLogger("deployment_utils")


def run_shell_command(command: str, capture_output: bool = True, check: bool = True) -> Optional[str]:
    """
    Запускает shell-команду и возвращает stdout, или None если не нужно.
    Если check=True, вызывает исключение при ошибке.
    """
    logger.info(f"Executing command: {command}")
    try:
        result = subprocess.run(
            command, shell=True, check=check,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True
        )
        if capture_output:
            logger.debug(f"Command output: {result.stdout.strip()}")
            return result.stdout.strip()
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Command '{command}' failed with code {e.returncode}: {e.stderr.strip() if e.stderr else e}")
        if check:
            raise
        return None


def check_service_status(service_name: str) -> bool:
    """
    Проверяет статус systemd-сервиса, возвращает True если активен.
    """
    cmd = f"systemctl is-active {service_name}"
    output = run_shell_command(cmd)
    is_active = output == "active"
    logger.info(f"Service '{service_name}' active: {is_active}")
    return is_active


def restart_service(service_name: str) -> None:
    """
    Перезапускает systemd-сервис, вызывает ошибку если не удаётся.
    """
    logger.info(f"Restarting service '{service_name}'")
    run_shell_command(f"sudo systemctl restart {service_name}", check=True)
    logger.info(f"Service '{service_name}' restarted successfully.")


def pull_git_branch(branch: str = "main", repo_path: str = ".") -> None:
    """
    Выполняет git pull указанной ветки в указанной директории.
    """
    logger.info(f"Pulling git branch '{branch}' in '{repo_path}'")
    cmd = f"git -C {repo_path} pull origin {branch}"
    run_shell_command(cmd, check=True)
    logger.info("Git pull completed.")


def install_requirements(requirements_path: str = "requirements.txt") -> None:
    """
    Устанавливает зависимости из requirements.txt через pip.
    """
    logger.info(f"Installing requirements from {requirements_path}")
    cmd = f"pip install -r {requirements_path}"
    run_shell_command(cmd, check=True)
    logger.info("Requirements installed.")


def migrate_database(migration_command: str = "aerich upgrade") -> None:
    """
    Запускает миграции базы данных (пример для aerich).
    """
    logger.info("Running database migrations")
    run_shell_command(migration_command, check=True)
    logger.info("Database migrations completed.")


def restart_uvicorn(service_name: str = "uvicorn.service") -> None:
    """
    Специфичный хелпер для перезапуска uvicorn через systemd.
    """
    restart_service(service_name)
