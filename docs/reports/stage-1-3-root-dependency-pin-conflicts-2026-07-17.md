# Этап 1.3 — Root dependency exact-pin conflicts

## Этап

Устранение `BASE-001`: десяти взаимоисключающих exact pins в объединённом
root development dependency graph.

## Обнаружено

| ID | Критичность | Компонент | Проблема | Причина | Последствие |
| --- | --- | --- | --- | --- | --- |
| BASE-001 | BLOCKER | Root Python dependencies | `requirements-dev.txt` включает `requirements.txt`, затем повторно pin-ит 10 packages к другим версиям | Runtime и dev version sets поддерживались независимо | pip resolver не может одновременно удовлетворить оба файла; devcontainer и tox заблокированы |
| DEP-001 | HIGH | CI contract | Repository audit не проверял конфликтующие exact pins | Dependency consistency отсутствовала в быстрых CI checks | Тот же blocker мог вернуться без явного CI failure |

Исходное состояние воспроизведено новым dependency parser на manifests из
`HEAD`:

```text
HEAD_CONFLICT_COUNT=10
HEAD_CONFLICT_PACKAGES=argon2-cffi,docker,jaeger-client,kubernetes,onnxruntime,opentelemetry-sdk,ray,scikit-learn,sphinx,tox
```

## Решение

Версии не обновлялись и новый package manager не вводился.

Из `requirements-dev.txt` удалены только повторные конфликтующие declarations.
Поскольку файл уже содержит `-r requirements.txt`, текущие root pins остаются
единственным фактическим значением для:

- `argon2-cffi`;
- `docker`;
- `jaeger-client`;
- `kubernetes`;
- `onnxruntime`;
- `opentelemetry-sdk`;
- `ray`;
- `scikit-learn`;
- `sphinx`;
- `tox`.

В dependency-free `tools/repository_audit.py` добавлены:

- нормализация package names по правилам `-`, `_`, `.`;
- извлечение exact `==` pins с extras и markers;
- ошибка CI при разных exact versions между root runtime/dev files.

Regression tests проверяют как обнаружение нормализованного конфликта, так и
текущее отсутствие конфликтов в реальных manifests.

## Изменённые файлы

- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\requirements-dev.txt`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\tools\repository_audit.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\tests\unit\test_repository_audit.py`
- `C:\Users\revav\.codex\visualizations\2026\07\16\019f6b1d-9500-72c1-a5db-0b389c382e23\aethernova-stabilization\docs\reports\stage-1-3-root-dependency-pin-conflicts-2026-07-17.md`

## Проверки

### Reproduction on HEAD

```text
Команда:
conflicting_exact_pins() для git show HEAD:requirements.txt и
git show HEAD:requirements-dev.txt во временном каталоге

Результат:
FAIL исходных manifests; blocker воспроизведён

Код завершения:
0 (диагностическая команда)

Вывод:
HEAD_CONFLICT_COUNT=10
HEAD_CONFLICT_PACKAGES=argon2-cffi,docker,jaeger-client,kubernetes,onnxruntime,opentelemetry-sdk,ray,scikit-learn,sphinx,tox
```

### Dependency audit regression tests

```text
Команда:
<isolated-python> -m pytest tests/unit/test_repository_audit.py -q

Результат:
PASS

Код завершения:
0

Вывод:
..                                                                       [100%]
2 passed, 1 warning in 0.07s
```

Локальное предупреждение создаётся `pytest-asyncio` на Python 3.14, а не
dependency audit test.

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

### Python compilation

```text
Команда:
<isolated-python> -m compileall -q tools/repository_audit.py tests/unit/test_repository_audit.py

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
| Системный архитектор | Root dependency ownership не перестроен; устранено только противоречие внутри существующей include-модели |
| Domain-архитектор | Domain code не затронут |
| Senior Python Engineer | Parser dependency-free, поддерживает extras/comments/markers и нормализованные имена |
| Database Engineer | Версии database packages не менялись |
| Security Engineer | Версии crypto/security packages не понижались; root pin остаётся source of truth |
| DevOps Engineer | Devcontainer/tox больше не получают логически несовместимый exact graph |
| SRE Engineer | Runtime package versions не изменены |
| QA Engineer | Добавлены positive detection и real-manifest regression tests |
| Performance Engineer | Audit остаётся быстрым и не вызывает pip/network |
| Reviewer | Удалены только десять дублирующих lines; новая проверка локальна и читаема |

## Риски

- Удаление exact-pin конфликтов доказывает логическую согласованность прямых
  pins, но не полную разрешимость всех transitive dependencies.
- Root requirements остаётся очень тяжёлым набором Web/AI/ML/Web3/DevOps
  dependencies без lock-файла.
- Полный `pip install -r requirements-dev.txt` не запускался на Python
  3.11/3.12; локальный Python 3.14 не входит в заявленную matrix и исказил бы
  проверку binary package availability.
- Component-specific requirements могут содержать независимые конфликты; этот
  этап проверяет только root include graph.

## Следующий шаг

Этап 1.4 — исправить `BASE-002`: направить Alembic на фактическое migration
tree и добавить dependency-free validation migration path/revisions, не
запуская миграции на пользовательской или production БД.
