# Этап 1.5 — Telegram Docker build context

## Этап

Устранение `BASE-003`: гарантированно сломанного и небезопасного Telegram
Docker COPY path.

## Обнаружено

| ID | Критичность | Компонент | Проблема | Причина | Последствие |
| --- | --- | --- | --- | --- | --- |
| BASE-003 | BLOCKER | `telegram_bot/Dockerfile` | Dockerfile копировал отсутствующие `.env` и `./entrypoints` | Фактические entrypoints находятся в `backend/entrypoints`, а secrets ожидались как build artifact | Image build останавливался на COPY до запуска |
| TGBOT-001 | CRITICAL | Telegram Docker context | Локальный `.env` предполагалось встраивать в image layer | Runtime configuration смешана с image assembly | Tokens, DSN и passwords могли сохраниться в image history/registry |
| TGBOT-002 | HIGH | Repository audit | CI не проверял существование local COPY sources и `.env` policy | Dockerfile contract проверялся только при полном build | Path/security regression обнаруживался поздно |

## Решение

- прямой `COPY .env /app/.env` удалён;
- entrypoints копируются из существующего `./backend/entrypoints`;
- runtime configuration продолжает передаваться через Compose/environment;
- добавлен `telegram_bot/.dockerignore`, исключающий `.env`, `.env.*`,
  caches, VCS metadata, tests/docs и неиспользуемые build assets;
- `.env.example` и `.env.template` явно разрешены как несекретные templates;
- repository audit dependency-free проверяет:
  - запрет direct `.env` COPY;
  - существование простых local COPY sources;
  - наличие непустого `.dockerignore`;
  - явное исключение `.env` из context;
- regression tests воспроизводят missing source, forbidden `.env` COPY и
  отсутствие `.env` ignore.

Изменение не добавляет секреты, не меняет env names и не запускает контейнер.

## Изменённые файлы

- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\telegram_bot\Dockerfile`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\telegram_bot\.dockerignore`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\tools\repository_audit.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\tests\unit\test_repository_audit.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\docs\reports\stage-1-5-telegram-docker-context-2026-07-17.md`

## Проверки

### Repository audit regression tests

```text
Команда:
<isolated-python> -m pytest tests/unit/test_repository_audit.py -q

Результат:
PASS

Код завершения:
0

Вывод:
.........                                                                [100%]
9 passed, 1 warning in 0.10s
```

Предупреждение относится к `pytest-asyncio` на локальном Python 3.14.

### Repository contract audit

```text
Команда:
python tools/repository_audit.py

Результат:
PASS с прежним предупреждением о LICENSE

Код завершения:
0

Вывод:
WARNING: LICENSE is empty; choose a license before publishing releases or packages
repository audit: 13244 tracked files, 0 error(s), 1 warning(s)
```

### Telegram Compose syntax

```text
Команда:
docker compose -f telegram_bot/docker-compose.yml config --quiet

Результат:
PASS

Код завершения:
0

Вывод:
WARNING: Error loading config file: open C:\Users\revav\.docker\config.json: Access is denied.
WARNING: Error loading config file: open C:\Users\revav\.docker\config.json: Access is denied.
```

Для interpolation использованы только синтетические test values.

### Docker BuildKit static check

```text
Команда:
docker build --check -f telegram_bot/Dockerfile telegram_bot

Результат:
BLOCKED внешним состоянием

Код завершения:
1

Вывод:
ERROR: failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine;
the system cannot find the file specified.
```

Docker Desktop daemon не запущен. Сначала sandbox также запрещал доступ к
Docker config; повторный разрешённый вызов дошёл до отсутствующего daemon.

### Formatter и lint

```text
Команда:
<isolated-python> -m black --check tools/repository_audit.py tests/unit/test_repository_audit.py
<isolated-python> -m flake8 tools/repository_audit.py tests/unit/test_repository_audit.py

Результат:
PASS

Код завершения:
0

Вывод:
All done! ✨ 🍰 ✨
2 files left unchanged.
```

## Десять независимых проверок

| Позиция | Результат |
| --- | --- |
| Системный архитектор | Runtime env contract сохранён, image/config boundaries усилены |
| Domain-архитектор | Booking/bot domain не затронут |
| Senior Python Engineer | Python runtime code не менялся |
| Database Engineer | DATABASE_URL contract не менялся |
| Security Engineer | `.env` исключён из COPY и build context |
| DevOps Engineer | Все local COPY sources существуют относительно Telegram context |
| SRE Engineer | Process commands и ports не менялись |
| QA Engineer | Три failure modes закреплены dependency-free tests |
| Performance Engineer | Tests/docs/caches исключены из context, уменьшая передачу данных daemon |
| Reviewer | Изменены два COPY/security rules без перестройки image |

## Риски

- Полная image build не подтверждена, пока Docker daemon выключен.
- `pip install -r requirements.txt` внутри image может иметь независимые
  package/platform blockers.
- Telegram Compose всё ещё объявляет RabbitMQ, который active queue client не
  использует.
- Worker запускает process-local notification queue, а не Redis Streams
  consumer.
- Compose содержит development `--reload`, published database/broker ports и
  небезопасные fallback credentials; production profile не сформирован.

## Следующий шаг

Проверить и стабилизировать observability wiring: Prometheus не должен scrape
несуществующий backend `/metrics`, а health/readiness должны быть отделены от
telemetry pipeline readiness.
