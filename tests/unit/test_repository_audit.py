from __future__ import annotations

from pathlib import Path

from tools.repository_audit import (
    ROOT,
    alembic_layout_errors,
    conflicting_exact_pins,
    docker_copy_errors,
    dockerignore_errors,
)


def test_conflicting_exact_pins_detects_normalized_package_names(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "requirements.txt"
    development = tmp_path / "requirements-dev.txt"
    runtime.write_text("Example_Package[extra]==1.0.0\n", encoding="utf-8")
    development.write_text("example-package==2.0.0\n", encoding="utf-8")

    assert conflicting_exact_pins(runtime, development) == [
        ("example-package", "1.0.0", "2.0.0")
    ]


def test_root_and_development_requirements_have_no_exact_pin_conflicts() -> None:
    assert (
        conflicting_exact_pins(
            ROOT / "requirements.txt",
            ROOT / "requirements-dev.txt",
        )
        == []
    )


def test_alembic_layout_rejects_empty_parallel_tree(tmp_path: Path) -> None:
    migration_root = tmp_path / "migrations"
    migration_root.mkdir()
    (migration_root / "env.py").touch()
    config = tmp_path / "alembic.ini"
    config.write_text(
        "[alembic]\n"
        "script_location = %(here)s/migrations\n"
        "version_locations = %(here)s/migrations/versions\n",
        encoding="utf-8",
    )

    errors = alembic_layout_errors(config)

    assert any("env.py is missing or empty" in error for error in errors)
    assert any("no Python revisions found" in error for error in errors)


def test_alembic_layout_rejects_invalid_post_write_interpolation(
    tmp_path: Path,
) -> None:
    migration_root = tmp_path / "alembic"
    versions = migration_root / "versions"
    versions.mkdir(parents=True)
    (migration_root / "env.py").write_text("# executable\n", encoding="utf-8")
    (versions / "0001.py").write_text("revision = '0001'\n", encoding="utf-8")
    config = tmp_path / "alembic.ini"
    config.write_text(
        "[alembic]\n"
        "script_location = %(here)s/alembic\n"
        "version_locations = %(here)s/alembic/versions\n"
        "[post_write_hooks]\n"
        "hooks = black\n"
        "black.options = -q %(rev_file)s\n",
        encoding="utf-8",
    )

    errors = alembic_layout_errors(config)

    assert any("invalid Alembic interpolation" in error for error in errors)


def test_backend_alembic_config_points_to_executable_tree() -> None:
    assert alembic_layout_errors(ROOT / "backend" / "alembic.ini") == []


def test_docker_copy_rejects_env_and_missing_sources(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "COPY .env /app/.env\n"
        "COPY ./missing /app/missing\n",
        encoding="utf-8",
    )

    errors = docker_copy_errors(dockerfile, tmp_path)

    assert any("must not embed .env" in error for error in errors)
    assert any("COPY source does not exist" in error for error in errors)


def test_telegram_dockerfile_copy_sources_are_safe_and_present() -> None:
    assert (
        docker_copy_errors(
            ROOT / "telegram_bot" / "Dockerfile",
            ROOT / "telegram_bot",
        )
        == []
    )


def test_dockerignore_requires_env_exclusion(tmp_path: Path) -> None:
    (tmp_path / ".dockerignore").write_text("__pycache__/\n", encoding="utf-8")

    assert dockerignore_errors(tmp_path) == [
        f"{tmp_path / '.dockerignore'}: .env is not excluded from the Docker context"
    ]


def test_telegram_docker_context_excludes_env_files() -> None:
    assert dockerignore_errors(ROOT / "telegram_bot") == []
