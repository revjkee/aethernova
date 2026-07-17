# Этап 1.2 — Identity Access fail-closed recovery access

## Этап

Устранение `BASE-005`: небезопасных значений по умолчанию и неявной
privileged identity в legacy `identity-access-core`.

## Обнаружено

| ID | Критичность | Компонент | Проблема | Причина | Последствие |
| --- | --- | --- | --- | --- | --- |
| BASE-005 | CRITICAL | Identity Access config | `emergency_admin`, auth bypass, debug и MFA-disable были включены по умолчанию | Recovery configuration проектировалась как постоянно активный emergency profile | Любой достижимый runtime создавал предсказуемую privileged identity с `*` |
| IAM-001 | CRITICAL | Identity Access status/backup | `get_status()` сериализовал весь config, включая encryption key и admin password | Использовался `config.dict()` без redaction | Секреты могли попасть в status consumer, backup JSON и логи |
| IAM-002 | BLOCKER | Identity Access config | Manifest требует Pydantic 2, но `BaseSettings` импортировался из `pydantic` | Не выполнена миграция на `pydantic-settings` | Конфигурация не импортируется в заявленном dependency profile |
| IAM-003 | HIGH | Identity Access tests/package | Обычный pytest пытается импортировать каталог `identity-access-core` как package; canonical `src/identity_access_core` пуст | Смешаны root scripts, invalid package directory name и пустой src layout | Полный suite и устанавливаемый runtime остаются заблокированы |
| IAM-004 | HIGH | Identity Access documentation | Recovery reports объявляли систему production-ready и публиковали default password | Исторический recovery status не был отделён от фактической readiness | Небезопасный runtime мог быть принят за готовый security foundation |

## Решение

Реализована fail-closed конфигурация без переноса ранее изолированного WIP:

- `emergency_admin_enabled`, `emergency_auth_bypass`, `debug` и
  `emergency_mfa_disabled` теперь по умолчанию `false`;
- auth bypass запрещён валидатором при любой попытке включения;
- break-glass account не создаётся без явного opt-in;
- opt-in требует пароль длиной не менее 16 символов без известных
  placeholder-значений;
- поскольку legacy flow не реализует MFA, его отсутствие должно быть явно
  подтверждено `emergency_mfa_disabled=true`; это не объявляется production
  MFA;
- `pydantic-settings` добавлен как доказанно необходимая зависимость для
  Pydantic 2;
- `public_dict()` исключает encryption key и admin password;
- status и shutdown backup используют только redacted config;
- health check проверяет отсутствие bypass и наличие admin только когда он
  явно включён;
- import-time print и изменение root logging level удалены из config module;
- legacy tests, которым нужен break-glass user, включают его только в
  test-only configuration;
- добавлены regression tests безопасных defaults, rejected unsafe config и
  redaction;
- пустой `tests/__init__.py` удалён: он не содержал API, но помечал tests как
  часть невалидного package tree;
- исторические README/status/recovery claims помечены как legacy и not
  production-ready.

Устанавливаемый `src/identity_access_core` намеренно не заполнен заглушками.
Его восстановление является отдельным packaging/runtime этапом.

## Изменённые файлы

- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\config.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\main.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\requirements.txt`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\src\authentication.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\tests\test_identity_access.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\tests\test_security_defaults.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\tests\__init__.py` — удалённый нулевой marker
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\README_RECOVERED.md`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\RECOVERY_REPORT.md`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\core-systems\identity-access-core\STATUS.md`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\docs\reports\stage-1-2-identity-access-fail-closed-2026-07-17.md`

## Проверки

### Regression tests безопасной конфигурации

```text
Команда:
<isolated-python> -m pytest tests/test_security_defaults.py -q --import-mode=importlib

Результат:
PASS

Код завершения:
0

Вывод:
......                                                                   [100%]
6 passed, 1 warning in 0.08s
```

Предупреждение создаётся `pytest-asyncio` на локальном Python 3.14 из-за
deprecated `asyncio.get_event_loop_policy`; оно не относится к production
коду и отсутствует в заявленной Python 3.11/3.12 matrix.

### Legacy service regression set

```text
Команда:
<isolated-python> -m pytest tests/test_identity_access.py tests/test_security_defaults.py -q --import-mode=importlib

Результат:
PASS

Код завершения:
0

Вывод:
.........................                                                [100%]
25 passed, 176 warnings in 9.10s
```

Большинство предупреждений связано с `pytest-asyncio`/Python 3.14 и legacy
datetime/Pydantic patterns. Они не скрыты и требуют отдельной совместимой
Python 3.11/3.12 проверки.

### Полный Identity Access suite

```text
Команда:
<isolated-python> -m pytest tests -q --import-mode=importlib

Результат:
BLOCKED

Код завершения:
1

Вывод:
ERROR collecting core-systems/identity-access-core/tests/test_main.py
ModuleNotFoundError: No module named 'identity_access_core'
1 error in 0.37s
```

Это подтверждает `IAM-003`: canonical src package пуст. Тест не отключён.

### Python compilation

```text
Команда:
<isolated-python> -m compileall -q config.py main.py src/authentication.py tests/test_identity_access.py tests/test_security_defaults.py

Результат:
PASS

Код завершения:
0

Вывод:
нет вывода
```

### Lint новых fail-closed paths

```text
Команда:
<isolated-python> -m flake8 config.py tests/test_security_defaults.py

Результат:
PASS

Код завершения:
0

Вывод:
нет вывода
```

### Formatter

```text
Команда:
<isolated-python> -m black --check
  core-systems/identity-access-core/config.py
  core-systems/identity-access-core/tests/test_security_defaults.py
  telegram_bot/backend/core/settings.py
  telegram_bot/tests/test_settings_security.py

Результат:
PASS

Код завершения:
0

Вывод:
All done! ✨ 🍰 ✨
4 files would be left unchanged.
```

Первый вызов с минимальной версией Black 23.3.0 был несовместим с локальным
Python 3.14 (`ast.Str`). Повторная проверка выполнена root-версией Black
24.4.2, которая входит в заявленный диапазон Identity Access `black>=23.0.0`.

### Unsafe defaults и secret print paths

```text
Команда:
rg по config.dict(), password print, default=True для admin/bypass

Результат:
PASS

Код завершения:
0 после нормализации отсутствия matches

Вывод:
NO_UNSAFE_IDENTITY_DEFAULT_OR_SECRET_PRINT_PATHS
```

### Patch integrity и repository audit

```text
Команда:
git -c core.longpaths=true diff --check
python tools/repository_audit.py

Результат:
PASS с прежним предупреждением о пустом LICENSE

Код завершения:
0

Вывод:
WARNING: LICENSE is empty; choose a license before publishing releases or packages
repository audit: 13237 tracked files, 0 error(s), 1 warning(s)
```

## Десять независимых проверок

| Позиция | Результат |
| --- | --- |
| Системный архитектор | Изменён только legacy recovery path; canonical empty src package не подменён параллельной реализацией |
| Domain-архитектор | User/RBAC/domain contracts не изменены; меняется только provisioning privileged recovery identity |
| Senior Python Engineer | Config переведён на заявленный Pydantic 2 settings API; import side effects уменьшены |
| Database Engineer | Persistence отсутствует и не изменялась; in-memory legacy limitation сохранена в рисках |
| Security Engineer | Default admin и bypass закрыты; unsafe opt-in rejected; secret status fields redacted |
| DevOps Engineer | Добавлена только доказанно необходимая `pydantic-settings`; env prefix сохранён |
| SRE Engineer | Health больше не требует отключённого admin, но проверяет policy safety; backups не включают secrets |
| QA Engineer | 6 security regressions и 19 legacy service tests проходят; full suite blocker показан |
| Performance Engineer | Удалены import-time print/log-level side effects; новых background operations нет |
| Reviewer | Нет массовых перемещений, фиктивного package runtime или ослабления тестов |

## Риски

- Explicit break-glass opt-in остаётся password-only legacy flow. Он требует
  явного подтверждения отсутствия MFA и не является production identity
  provider.
- `emergency_encryption_key` генерируется заново при запуске, если не задан
  извне; это ломает межпроцессную/межрестартовую JWT continuity.
- Users, sessions и failed-attempt state хранятся в памяти процесса.
- `src/identity_access_core`, Dockerfile, pyproject и uv lock остаются пустыми;
  install/build/runtime paths не восстановлены.
- Обычный `python main.py` и стандартный pytest collection остаются частью
  `BASE-006` и требуют отдельного package-layout решения.
- Full tests на заявленных Python 3.11/3.12 ещё не запускались.

## Следующий шаг

Этап 1.3 — устранить root dependency resolver blocker `BASE-001`: убрать 10
противоречащих exact pins из объединённого dev dependency graph, не обновляя
версии и не затрагивая component-specific manifests.
