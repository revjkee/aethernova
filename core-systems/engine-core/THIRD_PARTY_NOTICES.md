# THIRD_PARTY_NOTICES

> DO NOT EDIT MANUALLY — this document is updated by CI from SBOM and license scanners.  
> Источник правды: SBOM (`sbom.repo.json`, `sbom.image.json`) и отчёт `pip-licenses`.  
> I cannot verify this.

Этот файл предоставляет уведомления о сторонних компонентах, используемых в составе продукта **engine-core** (исходные коды, бинарные артефакты, контейнерные образы). Он предназначен для выполнения требований OSS‑лицензий (атрибуция, уведомления, тексты лицензий, исходные коды при необходимости).

---

## 0) Версии и контроль целостности

- Продукт: `engine-core`
- Версия продукта: см. файл `VERSION`
- Git commit: `${GIT_SHA}` (подставляется CI)
- Дата сборки: `${BUILD_DATE}` (UTC)
- Образ контейнера: `${DOCKER_IMAGE}:${DOCKER_TAG}`
- Контрольные файлы:
  - SBOM (репозиторий): `sbom.repo.json`
  - SBOM (образ): `sbom.image.json`
  - Отчёт лицензий Python: `licenses-py.json`
  - Архив текстов лицензий: `third_party_licenses.tar.gz`

> Проверка целостности: CI публикует SHA256 каждого артефакта в Release Assets.

---

## 1) Методология сбора сведений

Сведения агрегируются автоматически из нескольких источников:

1. **Python‑зависимости:** `pip-licenses` (режим JSON) по экспортированному `requirements.txt` из Poetry.
2. **SBOM:** `syft` по исходникам и по финальному контейнерному образу (detector: pypi, os‑packages, files).
3. **Скан лицензий и рисков:** `grype` (лицензии/уязвимости) — справочная информация.
4. **Вендорные артефакты:** базовый Docker‑образ, системные пакеты, шрифты/иконки.

Команды (выполняются в CI; отражены здесь для прозрачности):

```bash
# Экспорт зависимостей Python (включая dev при необходимости)
poetry export -f requirements.txt --with dev --without-hashes -o licenses.requirements.txt

# Отчёт по лицензиям Python
pip-licenses --format=json --with-authors --with-urls --with-license-file \
  --from=mixed --ignore-packages pip setuptools wheel \
  > licenses-py.json

# SBOM для репозитория (исходники)
syft packages dir:. -o json > sbom.repo.json

# SBOM для образа
syft "$DOCKER_IMAGE:$DOCKER_TAG" -o json > sbom.image.json

# Архив текстов лицензий (из вывода pip-licenses)
pip-licenses --format=plain-vertical --with-license-file --no-license-path \
  | awk '/License file/ {print $$3}' | xargs -I{} tar -rvf third_party_licenses.tar {}
gzip -f third_party_licenses.tar
