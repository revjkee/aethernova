mythos-core/README.md

# Mythos Core

Модуль «Mythos Core» — это каноническое ядро лора и правил Aethernova/NeuroCity. Он хранит неизменяемые основы мира (скрижали, сущности, роли, каноны), обеспечивает валидацию и эволюцию мифа через управляемые изменения (proposals), а также предоставляет согласованные API/схемы для всех подсистем (игровой движок, агенты ИИ, DAO, Web3-модули).

## Ключевая ценность

- **Единый источник истины**: централизованный реестр канонических объектов (скрижали, ангелы, артефакты, законы, хронология).
- **Формальные контракты**: строгие JSON-схемы для валидации и поставки данных в другие ядра.
- **Управляемая эволюция**: процесс предложений/голосований с журналированием и криптографической фиксацией версий.
- **Аудит и трассируемость**: неизменяемые записи об изменениях, подписи, ссылки на on-chain артефакты (при наличии).

---

## Архитектура (обзор)



mythos-core/
├── README.md
├── LICENSE
├── docs/
│ ├── adr/ # Architecture Decision Records
│ ├── glossary.md # Термины и определения
│ └── schemas/ # Канонические JSON-схемы
├── data/
│ ├── canon/ # Версионированные каноны (JSON/YAML)
│ └── proposals/ # Предложения на изменение
├── src/
│ ├── mythos_core/
│ │ ├── registry.py # Реестр и индексы канона
│ │ ├── validator.py # Валидация по схемам, миграции
│ │ ├── provenance.py # Подписи, хеши, цепочки происхождения
│ │ ├── api.py # Внутренний API: загрузка, запросы, диффы
│ │ └── cli.py # CLI-утилиты (lint, validate, diff, release)
│ └── ...
└── tests/
├── unit/
└── integration/


### Доменная модель (сжатая)

- `Tablet` (Скрижаль): базовый закон/принцип мира (id, title, text, version, signatures[]).
- `Angel`: мета-сущность (id, name, mandate, domains[], links[]).
- `CanonItem`: общий тип канона (type, payload, refs[]).
- `Chronicle`: хронология (events[], time_refs).
- `Proposal`: предложение изменения (diff, author, signatures[], status).
- `Release`: зафиксированный срез канона (tag, semver, hash, date, author).

---

## Контракты данных (JSON-схемы)

Примеры минимальных схем (см. `docs/schemas`):

```json
// docs/schemas/tablet.schema.json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "tablet.schema.json",
  "title": "Tablet",
  "type": "object",
  "required": ["id", "title", "text", "version"],
  "properties": {
    "id": { "type": "string", "pattern": "^[a-z0-9-]{3,64}$" },
    "title": { "type": "string", "minLength": 3 },
    "text": { "type": "string", "minLength": 10 },
    "version": { "type": "string", "pattern": "^v\\d+\\.\\d+\\.\\d+$" },
    "signatures": {
      "type": "array",
      "items": { "$ref": "signature.schema.json" }
    },
    "labels": { "type": "array", "items": { "type": "string" } }
  },
  "additionalProperties": false
}

// docs/schemas/proposal.schema.json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "proposal.schema.json",
  "title": "Proposal",
  "type": "object",
  "required": ["id", "author", "created_at", "changes", "status"],
  "properties": {
    "id": { "type": "string", "pattern": "^[A-Z]{2,5}-\\d{1,6}$" },
    "author": { "type": "string", "minLength": 3 },
    "created_at": { "type": "string", "format": "date-time" },
    "status": { "type": "string", "enum": ["draft", "review", "approved", "rejected", "merged"] },
    "changes": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["target", "op", "payload"],
        "properties": {
          "target": { "type": "string", "enum": ["tablet", "angel", "canon", "chronicle"] },
          "op": { "type": "string", "enum": ["create", "update", "delete"] },
          "payload": { "type": "object" }
        },
        "additionalProperties": false
      }
    },
    "signatures": {
      "type": "array",
      "items": { "$ref": "signature.schema.json" }
    }
  },
  "additionalProperties": false
}

Публичные интерфейсы
Внутренний Python-API (эскиз)
from mythos_core.registry import CanonRegistry
from mythos_core.validator import validate_item, validate_proposal
from mythos_core.provenance import sign_blob, verify_blob

reg = CanonRegistry.from_path("./data/canon")
tablet = reg.get("tablet", "law-of-balance:v1.0.0")
validate_item("tablet", tablet)

# применение предложения
prop = load_json("./data/proposals/ANG-12.json")
validate_proposal(prop)
diff = reg.apply_proposal(prop)
reg.save_release(tag="v1.2.0", author="mythos-bot")

CLI (эскиз)
mythos lint           # проверка стиля и схем
mythos validate       # валидация всех канонов и предложений
mythos diff --from v1.1.0 --to workspace
mythos release --tag v1.2.0 --author "mythos-bot"
mythos sign --file data/canon/tablets/law.json --key .keys/ed25519.pem

Нефункциональные требования

Безопасность и происхождение

Подписи (Ed25519) для релизов и критичных объектов; хранение *.sig + sha256.

Политика неизменяемости: изменения только через Proposal с журналом.

На уровне API — запрет «сквозных» произвольных полей additionalProperties=false.

Надежность и консистентность

Все данные проходят схемную валидацию до публикации.

Семантические версии релизов MAJOR.MINOR.PATCH.

Производительность

Индексирование по id/type/labels/version.

Кэширование валидированных артефактов (локальный кэш + хэши).

Аудит и наблюдаемость

Логи: события жизненного цикла (validate/apply/release) с trace-id.

Хранение диффов для каждого Proposal.

Качество и процессы
CI/CD (минимальные проверки)

lint: black/ruff (Python), markdownlint (docs), jsonlint.

validate: схемы JSON (docs/schemas/*.json) против data/canon/**.

unit: быстрые тесты на валидацию, диффы, подписи.

integration: сценарии применения Proposal и сборки релиза.

supply-chain: генерация SBOM (CycloneDX), подпись релизов.

Тестирование (минимальные цели покрытия)

Валидация по схемам: 100% путей ошибок/успеха для ключевых схем.

Apply Proposal: создание/обновление/удаление с конфликтами.

Подписи: позитивные/негативные кейсы verify.

Правила изменений (governance)

Изменения канона через Proposal + 2-из-N одобрения группы хранителей.

Любая несовместимая правка требует MAJOR-релиз.

Каждая таблица канона (canon/*) должна быть привязана к схеме + версии.

Версионирование

SemVer: vX.Y.Z.

Теги релизов mythos-core@vX.Y.Z.

Данные канона релизятся атомарно с неизменяемым хэшем каталога.

Локальная разработка (быстрый старт)
git clone <repo> && cd mythos-core
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"                 # зависимости разработчика
make lint validate test                 # базовые проверки
python -m mythos_core.cli validate      # запустить валидацию

Безопасность

Уязвимости и инциденты: фиксируйте частным каналом владельцам репозитория. Не размещайте приватные ключи и секреты в репозитории. Все ключи — только в безопасных хранилищах.