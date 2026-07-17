# Этап 1.1 — Telegram settings secret leak

## Этап

Устранение `BASE-004`: import-time утечки секретов из Telegram settings.

## Обнаружено

| ID | Критичность | Компонент | Проблема | Причина | Последствие |
| --- | --- | --- | --- | --- | --- |
| BASE-004 | CRITICAL | `telegram_bot/backend/core/settings.py` | Импорт модуля печатал весь `settings.model_dump()` | В production import path оставлен debug `print` | Telegram token, database URL и парольные значения попадали в stdout и централизованные логи |

Воспроизведение выполнено на версии файла из исходного `HEAD` с четырьмя
уникальными синтетическими секретами. Содержимое значений в отчёт не
выводилось:

```text
HEAD_SECRET_VALUES_EXPOSED=4
HEAD_OUTPUT_BYTES=510
```

## Решение

Удалён импортный `print` полной конфигурации. Публичный объект `settings`,
переменные окружения, их типы и пути импорта не изменены.

Добавлен regression test, который:

1. создаёт дочерний Python process с синтетическими секретами;
2. импортирует `backend.core.settings`;
3. проверяет успешный импорт;
4. проверяет, что ни одно секретное значение не появилось в stdout или stderr.

Subprocess выбран намеренно: он изолирует module import cache и проверяет
реальный import-time contract.

## Изменённые файлы

- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\telegram_bot\backend\core\settings.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\telegram_bot\tests\test_settings_security.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\docs\reports\stage-1-1-telegram-settings-secret-leak-2026-07-17.md`

## Проверки

### Воспроизведение на исходном HEAD

```text
Команда:
Изолированное исполнение git show HEAD:telegram_bot/backend/core/settings.py
с redirect_stdout и четырьмя синтетическими секретами.

Результат:
FAIL исходной версии; утечка воспроизведена.

Код завершения:
0 (диагностическая команда)

Вывод:
HEAD_SECRET_VALUES_EXPOSED=4
HEAD_OUTPUT_BYTES=510
```

### Regression test

```text
Команда:
<isolated-python> -m pytest telegram_bot/tests/test_settings_security.py -q

Результат:
PASS

Код завершения:
0

Вывод:
.                                                                        [100%]
1 passed in 0.54s
```

### Telegram test directory

```text
Команда:
<isolated-python> -m pytest telegram_bot/tests -q

Результат:
PASS

Код завершения:
0

Вывод:
.                                                                        [100%]
1 passed in 0.53s
```

### Python compilation

```text
Команда:
<isolated-python> -m compileall -q telegram_bot/backend/core/settings.py telegram_bot/tests/test_settings_security.py

Результат:
PASS

Код завершения:
0

Вывод:
нет вывода
```

### Formatting

```text
Команда:
<isolated-python> -m black --check telegram_bot/backend/core/settings.py telegram_bot/tests/test_settings_security.py

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
<isolated-python> -m flake8 telegram_bot/backend/core/settings.py telegram_bot/tests/test_settings_security.py

Результат:
PASS

Код завершения:
0

Вывод:
нет вывода
```

### Повторный поиск опасного пути

```text
Команда:
rg -n "print\(.*settings|settings\.model_dump\(\)" telegram_bot/backend --glob "*.py"

Результат:
PASS

Код завершения:
1 от rg, нормализован диагностической командой в 0

Вывод:
NO_SETTINGS_PRINT_PATHS
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

### Patch integrity

```text
Команда:
git -c core.longpaths=true diff --check

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
| Системный архитектор | Dependency direction и public settings contract не изменены |
| Domain-архитектор | Domain model не затронута |
| Senior Python Engineer | Удалён import side effect; тест использует изолированный subprocess |
| Database Engineer | DSN contract не изменён; значение больше не печатается |
| Security Engineer | Подтверждённое раскрытие четырёх secret categories устранено regression test |
| DevOps Engineer | Env names и container injection contract не изменены |
| SRE Engineer | Секреты больше не попадают в process stdout/stderr при импорте |
| QA Engineer | Тест сначала воспроизводит исходную причину через HEAD, затем проверяет текущий код |
| Performance Engineer | Удалён лишний import-time I/O |
| Reviewer | Изменение минимально: удалены три строки, добавлен один узкий тест |

## Риски

- Тест закрывает import-time вывод именно `backend.core.settings`; другие
  компоненты репозитория требуют отдельного secret logging audit.
- Поля секретов пока имеют тип `str`, а не `SecretStr`. Их изменение затронуло
  бы потребителей и не входит в этот минимальный fix.
- Временное тестовое окружение использовало Python 3.14, потому что это
  доступный локальный interpreter. CI/container compatibility с заявленными
  Python 3.11/3.12 должна проверяться отдельно.
- Telegram Dockerfile остаётся заблокированным `BASE-003`; образ не собирался
  в рамках этого security fix.

## Следующий шаг

Этап 1.2 — перевести emergency privileged identity в
`identity-access-core` в fail-closed режим с проверкой конфигурации и
regression tests, не перенося ранее изолированный WIP.
