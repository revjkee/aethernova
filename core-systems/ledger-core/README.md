# ledger-core/README.md

# Ledger Core

Промышленное ядро бухгалтерского учёта (двойная запись, неизменяемый журнал, детерминируемые сальдо) с ACID‑гарантиями, идемпотентностью операций и полным аудит‑трейлом. Подходит для финтех‑продуктов, биллинга, внутренних расчётов и токенизированных систем балансов.

## Ключевые свойства

- **Двухзаписная модель**: каждая проводка имеет сумму дебет = кредит, исключая рассинхронизацию.
- **Неизменяемый журнал**: записи только добавляются; исправления — через сторнирующие проводки.
- **ACID**: транзакционность на уровне БД, сериализуемая семантика при постинге проводок.
- **Идемпотентность**: каждый `posting` принимает `idempotency_key`, что гарантирует единожды‑выполнение.
- **Снимки (snapshots)**: ускорение агрегатов без потери доказуемости.
- **Аудит**: полная трассировка операций, подписи хеш‑цепи (опционально).
- **Наблюдаемость**: метрики Prometheus, структурированные логи, трассировка.
- **Миграции**: версионирование схемы БД.
- **Расширяемость**: плагины валидации бизнес‑правил (pre/post hooks).
- **Безопасность**: RBAC на уровне API, валидация входных данных, защитные лимиты.

## Архитектура

┌──────────┐ ┌───────────────┐ ┌───────────────────┐
│ Clients │ <-- │ HTTP/gRPC │ --> │ Command Handler │
└──────────┘ └───────────────┘ └────────┬──────────┘
│
┌───────▼─────────┐
│ Domain Model │
│ (Double-entry) │
└───────┬─────────┘
┌───────────▼───────────┐
│ Persistence (DB) │
│ journal, accounts, │
│ balances, snapshots │
└───────────┬───────────┘
┌───────▼─────────┐
│ Observability │
│ metrics/logs/tr │
└────────────┬────┘
┌───▼──────┐
│ RBAC │
└──────────┘

markdown
Копировать
Редактировать

### Модель данных (PostgreSQL)

- `accounts(account_id PK, currency, metadata JSONB, created_at)`
- `journal(entry_id PK, ts, batch_id, idempotency_key UNIQUE, description, metadata JSONB)`
- `postings(entry_id FK -> journal, line_no, debit_account, credit_account, amount, currency, metadata JSONB, PRIMARY KEY(entry_id, line_no))`
- `balances(account_id, currency, as_of_ts, amount, PRIMARY KEY(account_id, currency, as_of_ts))` — снапшоты.
- `constraints`:
  - сумма по дебету = сумме по кредиту в пределах `entry_id`
  - `amount > 0`
  - `currency` согласуется между счётом и проводкой.

Опционально:
- `hash_chain(entry_id, prev_hash, curr_hash)` — криптографическая связность журнала (включая сериализацию всех строк проводок).

## Гарантии согласованности

- Все проводки валидируются в одной транзакции с уровнем изоляции `REPEATABLE READ` или выше.
- При конкурентном постинге используется блокировка затрагиваемых счетов (оптимистичный upsert снапшотов + детект конфликтов).
- Идемпотентность: повторная попытка с тем же `idempotency_key` возвращает тот же результат (RFC‑style).

## API

### HTTP (REST)

`POST /v1/entries`
```json
{
  "idempotency_key": "c9f4c1c2-4a83-4d9a-8b20-6ab52a6a5c8c",
  "description": "Payout #12345",
  "metadata": {"origin":"payroll"},
  "postings": [
    {
      "debit_account": "cash:bank:operational",
      "credit_account": "revenue:services",
      "amount": "1250.00",
      "currency": "USD",
      "metadata": {"invoice_id":"INV-001"}
    }
  ]
}
Ответ 201 Created:

json
Копировать
Редактировать
{
  "entry_id": "01JC5E5M2Y72M9J0RZ3N9W9T3V",
  "ts": "2025-08-15T08:30:25Z",
  "hash": "f2a4…",
  "warnings": []
}
GET /v1/accounts/{account_id}/balance?currency=USD&as_of=2025-08-15T00:00:00Z

GET /v1/entries/{entry_id}

POST /v1/accounts — создание счёта
GET /v1/health — liveness/readiness

Коды ошибок:

400 — валидация; 409 — конфликт идемпотентности/версионирования; 422 — бизнес‑правила; 500 — внутренняя ошибка.

gRPC
Сервис LedgerService:

PostEntry(PostEntryRequest) returns (PostEntryResponse)

GetEntry(GetEntryRequest) returns (GetEntryResponse)

GetBalance(GetBalanceRequest) returns (GetBalanceResponse)

CreateAccount(CreateAccountRequest) returns (CreateAccountResponse)

StreamEntries(StreamEntriesRequest) returns (stream Entry)

Соглашения:

Все денежные поля — десятичные строки (lossless) либо int64 minor_units (единицы наименьшего разряда) — выбирается при сборке.

Обязателен idempotency_key для PostEntry.

Инварианты домена
Сумма по дебету = сумме по кредиту в рамках проводки.

Счета имеют единую валюту; кросс‑валютные операции допускаются только через пары счетов FX с явной фиксацией курса во metadata.

Отмена = зеркальная проводка со ссылкой на исходную entry_id (сервис гарантирует отсутствие «дыр»).

Производительность
Агрегирование сальдо из журнала O(N) заменяется на чтение снапшота + инкрементальные дельты.

Пакетная загрузка: POST /v1/entries:batch с дедупликацией по ключам.

Индексы: postings(debit_account), postings(credit_account), journal(idempotency_key unique), balances(account_id,currency,as_of_ts).

Транзакционная вставка ~ десятки тысяч линий/сек на типовом железе (зависит от конфигурации БД).

Безопасность
RBAC: роли admin, poster, reader (минимально необходимый доступ).

Валидация: строгая схема запросов; лимиты на размер батча/описания/metadata.

Идентификация: mTLS/gRPC, OAuth2/JWT для HTTP.

Аудит‑лог: все мутации включают actor_id, ip, user_agent.

Подписи (опционально): hash_chain для детектирования пост‑фактум изменений.

Конфигурация
Переменные окружения:

LEDGER_DB_DSN — строка подключения к Postgres.

LEDGER_API_HTTP_ADDR — адрес HTTP (по умолчанию 0.0.0.0:8080).

LEDGER_API_GRPC_ADDR — адрес gRPC (по умолчанию 0.0.0.0:9090).

LEDGER_MAX_BATCH — предел строк в батче (по умолчанию 500).

LEDGER_ENABLE_HASH_CHAIN — true|false.

LEDGER_DECIMAL_MODE — decimal|string|minor_units.

Миграции
Схема версионируется: /migrations (например, с использованием Liquibase/Flyway).

Правило: только добавления и обратные совместимые изменения в v1; breaking‑changes → новая мажорная версия API/схемы.

Наблюдаемость
Prometheus:

ledger_post_entry_latency_seconds{status="ok|error"}

ledger_post_entry_total{status=…}

ledger_db_tx_retries_total

ledger_balance_read_latency_seconds

Логи: JSON‑формат, кореляция trace_id, idempotency_key.

Трассировка: OpenTelemetry (экспорт в OTLP).

Тестирование
Unit: валидация инвариантов, идемпотентность, ошибки бизнес‑правил.

Contract: gRPC/HTTP схемы, совместимость.

Property‑based: генерация случайных батчей с проверкой равенства дебет/кредит.

Интеграционные: транзакции БД, конкурентные постинги, восстановление после сбоев.

Запуск:

bash
Копировать
Редактировать
pytest -q
SLO
Доля успешных PostEntry ≥ 99.9% за 30 дней.

P99 latency PostEntry ≤ 200 мс при целевом QPS.

Доступность API ≥ 99.95%.

Релизы и версионирование
Семантическое версионирование: vMAJOR.MINOR.PATCH.

Каждый релиз фиксирует миграции и совместимость API.

Чейнжлоги обязательны.

Быстрый старт (локально)
bash
Копировать
Редактировать
export LEDGER_DB_DSN="postgres://user:pass@localhost:5432/ledger?sslmode=disable"
make migrate
make run
curl -s -X GET http://127.0.0.1:8080/v1/health
Дорожная карта
Консистентные кросс‑валютные проводки (FX‑пулы).

Плагин лимитов и резервов.

Архивирование старых записей (cold storage) без потери проверяемости.

Формальные спецификации на основе TLA+/Alloy (опционально).

Лицензия
Проект распространяется на условиях Apache License 2.0 (см. LICENSE).

sql
Копировать
Редактировать

```text
# ledger-core/LICENSE

Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

"License" shall mean the terms and conditions for use, reproduction,
and distribution as defined by Sections 1 through 9 of this document.

"Licensor" shall mean the copyright owner or entity authorized by
the copyright owner that is granting the License.

"Legal Entity" shall mean the union of the acting entity and all
other entities that control, are controlled by, or are under common
control with that entity. For the purposes of this definition,
"control" means (i) the power, direct or indirect, to cause the
direction or management of such entity, whether by contract or
otherwise, or (ii) ownership of fifty percent (50%) or more of the
outstanding shares, or (iii) beneficial ownership of such entity.

"You" (or "Your") shall mean an individual or Legal Entity
exercising permissions granted by this License.

"Source" form shall mean the preferred form for making modifications,
including but not limited to software source code, documentation
source, and configuration files.

"Object" form shall mean any form resulting from mechanical
transformation or translation of a Source form, including but
not limited to compiled object code, generated documentation,
and conversions to other media types.

"Work" shall mean the work of authorship, whether in Source or
Object form, made available under the License, as indicated by a
copyright notice that is included in or attached to the work
(an example is provided in the Appendix below).

"Derivative Works" shall mean any work, whether in Source or Object
form, that is based on (or derived from) the Work and for which the
editorial revisions, annotations, elaborations, or other modifications
represent, as a whole, an original work of authorship. For the purposes
of this License, Derivative Works shall not include works that remain
separable from, or merely link (or bind by name) to the interfaces of,
the Work and Derivative Works thereof.

"Contribution" shall mean any work of authorship, including
the original version of the Work and any modifications or additions
to that Work or Derivative Works thereof, that is intentionally
submitted to Licensor for inclusion in the Work by the copyright owner
or by an individual or Legal Entity authorized to submit on behalf of
the copyright owner. For the purposes of this definition, "submitted"
means any form of electronic, verbal, or written communication sent
to the Licensor or its representatives, including but not limited to
communication on electronic mailing lists, source code control systems,
and issue tracking systems that are managed by, or on behalf of, the
Licensor for the purpose of discussing and improving the Work, but
excluding communication that is conspicuously marked or otherwise
designated in writing by the copyright owner as "Not a Contribution."

"Contributor" shall mean Licensor and any individual or Legal Entity
on behalf of whom a Contribution has been received by Licensor and
subsequently incorporated within the Work.

2. Grant of Copyright License.

Subject to the terms and conditions of this License, each Contributor
hereby grants to You a perpetual, worldwide, non-exclusive, no-charge,
royalty-free, irrevocable copyright license to reproduce, prepare
Derivative Works of, publicly display, publicly perform, sublicense,
and distribute the Work and such Derivative Works in Source or Object
form.

3. Grant of Patent License.

Subject to the terms and conditions of this License, each Contributor
hereby grants to You a perpetual, worldwide, non-exclusive, no-charge,
royalty-free, irrevocable (except as stated in this section) patent
license to make, have made, use, offer to sell, sell, import, and
otherwise transfer the Work, where such license applies only to those
patent claims licensable by such Contributor that are necessarily
infringed by their Contribution(s) alone or by combination of their
Contribution(s) with the Work to which such Contribution(s) was submitted.
If You institute patent litigation against any entity (including a
cross-claim or counterclaim in a lawsuit) alleging that the Work or a
Contribution incorporated within the Work constitutes direct or
contributory patent infringement, then any patent licenses granted to
You under this License for that Work shall terminate as of the date such
litigation is filed.

4. Redistribution.

You may reproduce and distribute copies of the Work or Derivative Works
thereof in any medium, with or without modifications, and in Source or
Object form, provided that You meet the following conditions:

(a) You must give any other recipients of the Work or Derivative Works a
copy of this License; and

(b) You must cause any modified files to carry prominent notices stating
that You changed the files; and

(c) You must retain, in the Source form of any Derivative Works that You
distribute, all copyright, patent, trademark, and attribution notices from
the Source form of the Work, excluding those notices that do not pertain
to any part of the Derivative Works; and

(d) If the Work includes a "NOTICE" text file as part of its distribution,
then any Derivative Works that You distribute must include a readable copy
of the attribution notices contained within such NOTICE file, excluding
those notices that do not pertain to any part of the Derivative Works, in
at least one of the following places: within a NOTICE text file distributed
as part of the Derivative Works; within the Source form or documentation,
if provided along with the Derivative Works; or, within a display generated
by the Derivative Works, if and wherever such third-party notices normally
appear. The contents of the NOTICE file are for informational purposes only
and do not modify the License. You may add Your own attribution notices
within Derivative Works that You distribute, alongside or as an addendum to
the NOTICE text from the Work, provided that such additional attribution
notices cannot be construed as modifying the License.

You may add Your own copyright statement to Your modifications and may
provide additional or different license terms and conditions for use,
reproduction, or distribution of Your modifications, or for any such
Derivative Works as a whole, provided Your use, reproduction, and
distribution of the Work otherwise complies with the conditions
stated in this License.

5. Submission of Contributions.

Unless You explicitly state otherwise, any Contribution intentionally
submitted for inclusion in the Work by You to the Licensor shall be
under the terms and conditions of this License, without any additional
terms or conditions. Notwithstanding the above, nothing herein shall
supersede or modify the terms of any separate license agreement you
may have executed with Licensor regarding such Contributions.

6. Trademarks.

This License does not grant permission to use the trade names,
trademarks, service marks, or product names of the Licensor,
except as required for reasonable and customary use in describing the
origin of the Work and reproducing the content of the NOTICE file.

7. Disclaimer of Warranty.

Unless required by applicable law or agreed to in writing, Licensor
provides the Work (and each Contributor provides its Contributions)
on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied, including, without limitation, any
warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY,
or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible for
determining the appropriateness of using or redistributing the Work
and assume any risks associated with Your exercise of permissions
under this License.

8. Limitation of Liability.

In no event and under no legal theory, whether in tort (including
negligence), contract, or otherwise, unless required by applicable law
(such as deliberate and grossly negligent acts) or agreed to in writing,
shall any Contributor be liable to You for damages, including any direct,
indirect, special, incidental, or consequential damages of any character
arising as a result of this License or out of the use or inability to use
the Work (including but not limited to damages for loss of goodwill,
work stoppage, computer failure or malfunction, or any and all other
commercial damages or losses), even if such Contributor has been advised
of the possibility of such damages.

9. Accepting Warranty or Additional Liability.

While redistributing the Work or Derivative Works thereof, You may choose
to offer, and charge a fee for, acceptance of support, warranty, indemnity,
or other liability obligations and/or rights consistent with this License.
However, in accepting such obligations, You may act only on Your own behalf
and on Your sole responsibility, not on behalf of any other Contributor,
and only if You agree to indemnify, defend, and hold each Contributor
harmless for any liability incurred by, or claims asserted against, such
Contributor by reason of your accepting any such warranty or additional
liability.

END OF TERMS AND CONDITIONS

APPENDIX: How to apply the Apache License to your work.

To apply the Apache License to your work, attach the following
boilerplate notice, with the fields enclosed by brackets "[]"
replaced with your own identifying information. (Don't include
the brackets!) The text should be enclosed in the appropriate
comment syntax for the file format. We also recommend that a
file or class name and description of purpose be included on the
same "printed page" as the copyright notice for easier
identification within third-party archives.

Copyright [2025] [Ledger Core Authors]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.







Спросить ChatGPT
