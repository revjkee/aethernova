from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


TELEGRAM_ROOT = Path(__file__).resolve().parents[1]


def test_settings_import_does_not_expose_secrets() -> None:
    secrets = {
        "TELEGRAM_TOKEN": "telegram-secret-value-for-regression-test",
        "DATABASE_URL": (
            "postgresql+asyncpg://settings-test-user:"
            "database-secret-value-for-regression-test@localhost/settings_test"
        ),
        "POSTGRES_PASSWORD": "postgres-secret-value-for-regression-test",
        "RABBITMQ_PASSWORD": "rabbitmq-secret-value-for-regression-test",
    }
    environment = os.environ.copy()
    environment.update(secrets)

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from backend.core.settings import settings; "
                "assert settings.telegram_token"
            ),
        ],
        cwd=TELEGRAM_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    output = result.stdout + result.stderr
    for secret in secrets.values():
        assert secret not in output
