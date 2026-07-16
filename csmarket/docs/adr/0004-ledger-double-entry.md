# 0004-ledger-double-entry
# ADR 0004: Ledger с двойной записью (double-entry) для CSMarket

Статус: Accepted
Дата: 2026-02-13
Контекст: CSMarket (внутренняя экономика и расчёты)
Решение: Double-entry ledger (двойная запись) как единый источник истины для денежных и квазиденежных движений

## TL;DR

Мы используем леджер двойной записи: каждое движение стоимости фиксируется как набор проводок (entries) по счетам (accounts), где сумма по транзакции равна нулю. Это даёт воспроизводимый аудит, детект ошибок по несходящимся дебету и кредиту, и корректные балансы при высокой конкурентности.

Факт: в двойной записи общий принцип состоит в том, что проводки должны балансироваться (total debits equals total credits), и это служит контрольной проверкой корректности учёта. Источники: Investopedia (общее описание двойной записи), ACCA (уравнение и равенство дебета и кредита), Martin Fowler (паттерны accounting entries и правило суммы в ноль). :contentReference[oaicite:0]{index=0}

## Контекст и проблема

CSMarket обрабатывает операции, которые влияют на ценность:
- ввод и вывод средств
- комиссии платформы
- удержания и резервы (например, hold до подтверждения обмена)
- расчёты между покупателем и продавцом
- возвраты и корректировки

Требования:
- возможность восстановить состояние балансов на любую дату
- неизменяемый аудит следа операций
- отсутствие расхождений при конкурентных запросах
- идемпотентность внешних событий (повторная доставка вебхука или повторный запрос пользователя)

## Решение

### 1. Модель учёта

1) Account (счёт)
- представляет контейнер стоимости для конкретного владельца и назначения
- типы: asset, liability, revenue, expense, equity (уровень типов зависит от потребностей домена)

Факт: типовая классификация счетов (asset, liability, equity, revenue, expense) используется в двойной записи. Источник: ACCA. :contentReference[oaicite:1]{index=1}

2) Transaction (транзакция леджера)
- единица бизнес-события, объединяющая набор entries
- содержит метаданные: инициатор, причина, внешняя ссылка, корреляционный идентификатор, время

3) Entry (проводка)
- атомарная строка движения по одному account
- фиксирует signed_amount (знаковое значение) и currency
- правило: сумма signed_amount по всем entries в рамках одной transaction должна быть равна нулю

Факт: правило “сумма entries равна нулю” как инвариант accounting transaction описано у Martin Fowler (multi-legged transaction). :contentReference[oaicite:2]{index=2}

### 2. Инварианты (обязательные ограничения)

Инвариант A: Баланс транзакции
- Для каждой transaction: SUM(entries.signed_amount) = 0 по каждой валюте.
Пояснение: это проектное требование, основанное на принципе двойной записи (баланс дебета и кредита). :contentReference[oaicite:3]{index=3}

Инвариант B: Неизменяемость
- entries не редактируются и не удаляются.
- исправления делаются отдельной корректирующей transaction, которая компенсирует ошибки.
Это проектное решение для аудитопригодности.

Инвариант C: Идемпотентность
- внешние события (платёжный провайдер, Steam-операции, бот-команды) должны иметь external_reference.
- external_reference уникален в пределах типа события и currency.
Это проектное решение для защиты от повторной доставки.

Инвариант D: Денежная точность
- amounts хранятся в минорных единицах (например, cents) как целые числа.
Это проектное решение для исключения ошибок float.

Инвариант E: Атомарность постинга
- создание transaction и всех entries выполняется в одной транзакции БД.
Это проектное решение для целостности.

### 3. Конкурентность и изоляция

Мы используем изоляцию Serializable для критичных операций постинга, и допускаем ретраи при serialization failure.

Факт: уровень Serializable в PostgreSQL может требовать повторов транзакций из-за serialization failures. Источник: PostgreSQL docs. :contentReference[oaicite:4]{index=4}

Практика:
- постинг выполняется в функции/сервисе, который ловит serialization failure и повторяет попытку ограниченное число раз
- все вычисления, влияющие на итоговые entries, выполняются внутри транзакции

### 4. Схема данных (логическая)

Account:
- id (uuid)
- owner_type, owner_id (например user, merchant, system)
- account_type (asset, liability, revenue, expense, equity)
- currency
- name
- status (active, frozen, closed)
- created_at

Transaction:
- id (uuid)
- external_reference (string, unique per source)
- correlation_id (uuid/string)
- reason_code (enum/string)
- created_at
- metadata (jsonb)

Entry:
- id (uuid)
- transaction_id (uuid, fk)
- account_id (uuid, fk)
- currency
- signed_amount (bigint)
- created_at
- entry_type (debit/credit опционально, если signed_amount уже задаёт знак)
- metadata (jsonb)

Примечание: debit/credit можно выводить из знака signed_amount; это проектный выбор. У Martin Fowler описана модель, где значения противоположных знаков представляют движение между счетами. :contentReference[oaicite:5]{index=5}

### 5. Правила проводок для домена CSMarket

Ниже правила являются проектным решением, а не утверждением факта.

Операция: Пополнение
- Debit: User Cash (asset) плюс
- Credit: Clearing/PayIn (liability) минус
- При подтверждении провайдера: перенос из Clearing в Platform Cash

Операция: Покупка скина
- Debit: User Cash минус
- Credit: Escrow (liability) плюс
- При успешной доставке:
  - Debit: Escrow минус
  - Credit: Seller Payable (liability) плюс
  - Fee:
    - Debit: Seller Payable минус
    - Credit: Platform Revenue (revenue) плюс

Операция: Вывод продавцу
- Debit: Seller Payable минус
- Credit: Payout Clearing (liability) плюс
- После подтверждения провайдера:
  - Debit: Payout Clearing минус
  - Credit: Platform Cash минус (или отдельный cash account провайдера)

### 6. Аудит и отчётность

Мы поддерживаем:
- журнал транзакций по external_reference и correlation_id
- выборку всех entries по account и диапазону дат
- расчёт баланса на дату как SUM(signed_amount) для account

Факт: “trial balance” как проверка равенства дебета и кредита используется в двойной записи для выявления ошибок. Источник: Stripe resource про trial balance. :contentReference[oaicite:6]{index=6}

### 7. Безопасность и контроль доступа

Это проектное решение.
- доступ к операциям постинга только через сервисный слой (не напрямую из API handlers)
- RBAC для чтения леджера:
  - пользователь видит только свои accounts
  - админ видит агрегаты и выборки по политике доступа
- неизменяемость entries защищается:
  - отсутствием UPDATE/DELETE в репозитории
  - правами БД (роль приложения без delete/update на таблицу entries)

### 8. Наблюдаемость

Это проектное решение.
- метрики: posting_latency, retries_serialization, ledger_post_failures
- логи: structured logs с correlation_id, transaction_id, external_reference
- алерты: рост serialization retries и рост несходящихся проверок (см. критерии)

## Альтернативы

1) Single-entry баланс
- отклонено из-за сложности аудита и риска расхождений при конкурентности

2) Материализованные балансы в таблице account_balance
- возможно как оптимизация чтения, но только как derived cache, а не source of truth
- источник истины остаётся entries

## Последствия

Плюсы:
- строгая целостность и аудитопригодность
- предсказуемость расчётов и восстановление состояния на дату

Минусы:
- больше записей на транзакцию (entries)
- необходимость ретраев на Serializable

## Критерии приёмки (проверяемые)

1) Инвариант ноль:
- для каждой transaction сумма entries по валюте равна нулю
- автоматическая проверка в тестах и периодический аудит job

2) Идемпотентность:
- повтор одной и той же операции с одинаковым external_reference не создаёт дубликат проводок

3) Неизменяемость:
- отсутствуют UPDATE/DELETE в коде
- роль приложения не имеет прав UPDATE/DELETE на entries

4) Конкурентность:
- при параллельных постингах нет отрицательных остатков там, где они запрещены политикой
- при serialization failure выполняется корректный retry

## Ссылки

- Double-entry overview and balancing principle: Investopedia. :contentReference[oaicite:7]{index=7}
- Accounting equation and equality of debits and credits: ACCA. :contentReference[oaicite:8]{index=8}
- Software accounting patterns and invariant sum to zero: Martin Fowler. :contentReference[oaicite:9]{index=9}
- Trial balance as validation in double-entry: Stripe resource. :contentReference[oaicite:10]{index=10}
- Serializable isolation and need to retry transactions: PostgreSQL documentation. :contentReference[oaicite:11]{index=11}
