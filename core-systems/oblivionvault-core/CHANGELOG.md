# oblivionvault-core/CHANGELOG.md
# Changelog

Все заметные изменения этого проекта фиксируются в этом файле.
Формат основан на принципах Keep a Changelog и семантическом версионировании (SemVer 2.0.0).

## Unreleased

### Added
- Шаблон разделов для последующих записей: Added / Changed / Deprecated / Removed / Fixed / Security.
- Ссылки сравнения (`[Unreleased]`) для удобной навигации между тегами.

### Changed
- 

### Deprecated
- 

### Removed
- 

### Fixed
- 

### Security
- 

## [0.1.0] - 2025-08-22
### Added
- Начальная инициализация журнала изменений в формате Keep a Changelog.
- Принята политика версионирования SemVer (MAJOR.MINOR.PATCH).
- Введены разделы `Unreleased`, `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
- Определены конвенции тегов релизов вида `v<MAJOR>.<MINOR>.<PATCH>` (например, `v0.1.0`).

---

## Политики и правила

### Семантическое версионирование
- **MAJOR** — несовместимые изменения API (breaking changes).
- **MINOR** — новая функциональность, обратно совместимая.
- **PATCH** — исправления ошибок, не меняющие API.

### Разделы
- **Added** — новая функциональность.
- **Changed** — изменения существующего поведения без ломки API.
- **Deprecated** — объявлено устаревшим; указать срок удаления.
- **Removed** — удалено (обычно после Deprecated).
- **Fixed** — исправления дефектов.
- **Security** — уязвимости и их устранение.

### Обязательные пометки для breaking changes
- Явно отмечайте `BREAKING:` в описании пункта и кратко указывайте миграционные шаги.

### Метки коммитов/PR (рекомендация)
- `type:feature`, `type:bug`, `type:docs`, `type:refactor`, `type:security`, `type:chore`.
- `scope:<модуль>` — необязательно (например, `scope:api`, `scope:db`).

---

## Ссылки на сравнение версий

> Замените `<REPO_URL>` на URL вашего репозитория (GitHub/GitLab/и т.п.).

- [Unreleased]: <REPO_URL>/compare/v0.1.0...HEAD
- [0.1.0]: <REPO_URL>/releases/tag/v0.1.0
