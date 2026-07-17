# Этап 1.4 — Backend Alembic migration path

## Этап

Устранение `BASE-002`: Alembic configuration указывала на пустое параллельное
migration tree и не могла прочитать post-write hooks.

## Обнаружено

| ID | Критичность | Компонент | Проблема | Причина | Последствие |
| --- | --- | --- | --- | --- | --- |
| BASE-002 | BLOCKER | `backend/alembic.ini` | `script_location` и `version_locations` указывали на `backend/migrations` | Реальные Alembic assets находятся в `backend/alembic` | Штатная команда не видела ни исполняемый env, ни revisions |
| DB-001 | BLOCKER | Alembic post-write hooks | Options использовали `%(rev_file)s` | Placeholder не соответствует Alembic 1.13.1 и ломает ConfigParser interpolation | Даже `alembic heads` падал до чтения revision graph |
| BASE-008 | HIGH | Backend metadata | Alembic env, runtime DB layer и models всё ещё не имеют общего metadata source | Несколько несогласованных DB implementations | Autogenerate/schema drift остаются ненадёжными после исправления пути |

Исходная layout-проверка:

```text
ConfiguredEnvExists=True
ConfiguredEnvBytes=0
ConfiguredVersionsExists=False
ActualEnvExists=True
ActualEnvBytes=6985
ActualVersionsExists=True
ActualRevisionCount=2
```

Первый Alembic CLI вызов после исправления каталога доказал независимый
post-write blocker:

```text
configparser.InterpolationMissingOptionError:
option 'black.options' ... interpolation key 'rev_file' ...
Raw value: '-q %(rev_file)s'
```

## Решение

- `script_location` изменён на `%(here)s/alembic`;
- `version_locations` изменён на `%(here)s/alembic/versions`;
- Black, isort и Ruff post-write hooks используют документированный
  установленным Alembic 1.13.1 token `REVISION_SCRIPT_FILENAME`;
- repository audit dependency-free проверяет:
  - наличие `[alembic]`;
  - корректную interpolation секции `post_write_hooks`;
  - непустой `env.py`;
  - наличие хотя бы одного Python revision в configured locations;
- regression tests воспроизводят пустое параллельное tree и неверный
  interpolation placeholder;
- ни одна БД не открывалась и ни одна migration не применялась.

`backend/migrations/env.py` не удалён: это требует отдельного доказательства
отсутствия внешних consumers. Он больше не является canonical Alembic path.

## Изменённые файлы

- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\backend\alembic.ini`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\tools\repository_audit.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\tests\unit\test_repository_audit.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\docs\reports\stage-1-4-backend-alembic-path-2026-07-17.md`

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
.....                                                                    [100%]
5 passed, 1 warning in 0.08s
```

Предупреждение относится к `pytest-asyncio` на локальном Python 3.14.

### Alembic heads

```text
Команда:
<isolated-python> -m alembic -c backend/alembic.ini heads

Результат:
PASS

Код завершения:
0

Вывод:
0002_add_security_incidents (head)
```

### Alembic history

```text
Команда:
<isolated-python> -m alembic -c backend/alembic.ini history

Результат:
PASS

Код завершения:
0

Вывод:
0001_initial -> 0002_add_security_incidents (head), add security_incidents table with enums, indexes and triggers
<base> -> 0001_initial, initial schema (users, roles, permissions, auth, audit)
```

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
repository audit: 13237 tracked files, 0 error(s), 1 warning(s)
```

### Formatter

```text
Команда:
<isolated-python> -m black --check tools/repository_audit.py tests/unit/test_repository_audit.py

Результат:
PASS

Код завершения:
0

Вывод:
All done! ✨ 🍰 ✨
2 files would be left unchanged.
```

### Lint

```text
Команда:
<isolated-python> -m flake8 tools/repository_audit.py tests/unit/test_repository_audit.py

Результат:
PASS

Код завершения:
0

Вывод:
нет вывода
```

## Десять независимых проверок

| Позиция | Результат |
| --- | --- |
| Системный архитектор | Каноническим выбран существующий непустой tree; параллельная архитектура не создана |
| Domain-архитектор | Domain/schema semantics миграций не менялись |
| Senior Python Engineer | Audit validation использует только stdlib и имеет regression coverage |
| Database Engineer | Revision chain читается; migrations не применялись без controlled DB |
| Security Engineer | DSN/secrets не читались и не публиковались |
| DevOps Engineer | Makefile/CLI config теперь разрешает фактический script tree |
| SRE Engineer | Изменений runtime startup/health нет |
| QA Engineer | Empty-tree и interpolation failures воспроизводятся unit tests |
| Performance Engineer | Проверка файловая, быстрая, без container/DB |
| Reviewer | Изменены два path, три placeholders и узкий audit contract |

## Риски

- `backend/alembic/env.py` не разрешает текущий `backend/src/db.py:Base` или
  `backend/src/models.py:metadata` как единый target metadata.
- `backend/src/models.py` расходится со схемами revisions.
- `DATABASE_URL`, `DB_PRIMARY_URL` и Alembic DSN policy не унифицированы.
- `upgrade`, `downgrade`, `check` и migration smoke test не запускались:
  controlled disposable PostgreSQL для этого этапа не создавался.
- Root Docker image не копирует Alembic config/revisions, поэтому container
  migration path требует отдельного deployment решения.
- Пустое прежнее `backend/migrations` tree пока сохранено до consumer audit.

## Следующий шаг

Сформировать безопасный commit текущих baseline и четырёх проверенных
стабилизационных этапов, затем продолжить `BASE-008` отдельным database
contract этапом.
