# Payments Domain

Статус: Production Draft  
Контекст: Reva Studio  
Область: `payments`  
Последнее обновление: 2026-03-23

## 1. Назначение домена

Домен `payments` отвечает за безопасную фиксацию денежных обязательств, создание платёжных намерений, подтверждение статуса оплаты, обработку webhook-событий платёжного провайдера, возвраты, отмены, сверку и предоставление единого платёжного состояния для бронирований, заказов и будущих подписок.

Этот домен не должен:
- хранить полные карточные данные;
- хранить CVV/CVC после авторизации;
- заменять бухгалтерский учёт;
- выполнять бизнес-логику расписания мастеров;
- принимать решение о политике скидок вне утверждённых правил ценообразования.

PCI SSC указывает, что PCI DSS применяется к средам, где данные платёжного аккаунта хранятся, обрабатываются или передаются, а хранение CVV после авторизации запрещено. Источники: PCI SSC Quick Reference Guide и PCI SSC FAQ.  
См.:
- https://www.pcisecuritystandards.org/standards/
- https://www.pcisecuritystandards.org/faq/articles/Frequently_Asked_Question/if-an-organization-provides-software-or-functionality-that-runs-on-a-consumer-s-device-for-example-smartphones-tablets-or-laptops-and-is-used-to-accept-payment-account-data-can-the-organization-store-card-verification-codes-for-those-consumers/
- https://blog.pcisecuritystandards.org/faq-can-cvc-be-stored-for-card-on-file-or-recurring-transactions

## 2. Архитектурная цель

Основная цель платежного домена в Reva Studio:

1. Не допустить двойного списания.
2. Не потерять подтверждение оплаты при сетевых сбоях.
3. Не считать клиентский callback источником истины.
4. Считать webhook провайдера главным асинхронным подтверждением внешнего платёжного состояния.
5. Хранить внутреннее состояние платежа отдельно от внешнего статуса PSP.
6. Обеспечить повторяемость операций через идемпотентность.
7. Свести PCI-объём к минимуму.

Stripe официально рекомендует использовать idempotency keys для безопасных повторов POST-запросов и проверять подписи webhook, используя raw body и endpoint secret.  
См.:
- https://docs.stripe.com/api/idempotent_requests
- https://docs.stripe.com/error-low-level
- https://docs.stripe.com/webhooks/signature
- https://docs.stripe.com/security/guide

## 3. Внешние регуляторные и стандартные ограничения

### 3.1 PCI DSS

PCI DSS определяет требования к защите сред, где данные платёжного аккаунта хранятся, обрабатываются или передаются. Для Reva Studio это означает:

- не хранить PAN, если это не требуется архитектурно;
- не хранить CVV/CVC после авторизации;
- не логировать чувствительные платёжные поля;
- минимизировать соприкосновение backend с карточными данными;
- использовать hosted checkout / provider-side tokenization, где это возможно.

Источники:
- https://www.pcisecuritystandards.org/standards/
- https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf
- https://www.pcisecuritystandards.org/faq/articles/Frequently_Asked_Question/if-an-organization-provides-software-or-functionality-that-runs-on-a-consumer-s-device-for-example-smartphones-tablets-or-laptops-and-is-used-to-accept-payment-account-data-can-the-organization-store-card-verification-codes-for-those-consumers/

### 3.2 PSD2 / SCA

Для европейских платёжных сценариев Strong Customer Authentication действует в рамках PSD2 и вступила в силу с 14 сентября 2019 года. Это влияет на логику подтверждения онлайн-платежей и обработку дополнительных шагов аутентификации.  
Источники:
- https://finance.ec.europa.eu/publications/strong-customer-authentication-requirement-psd2-comes-force_en
- https://finance.ec.europa.eu/regulation-and-supervision/financial-services-legislation/implementing-and-delegated-acts/payment-services-directive_en
- https://eur-lex.europa.eu/eli/reg_del/2018/389/oj/eng

## 4. Границы bounded context

Домен `payments` взаимодействует со следующими контекстами:

- `bookings`: платёж привязывается к записи или предоплате за запись;
- `pricing`: итоговая сумма и скидки рассчитываются до создания платежа;
- `loyalty`: бонусы могут уменьшать payable amount или начисляться после подтверждения;
- `notifications`: уведомления об оплате и возврате;
- `ledger` или `accounting` в будущем: финансовая сверка, отчётность;
- `identity`: связь платежа с пользователем и оператором;
- `audit`: неизменяемая фиксация значимых действий.

Граница ответственности:
- `payments` знает сумму, валюту, платёжный метод, внешний идентификатор PSP, статусы и финансовый результат;
- `payments` не определяет, можно ли вообще бронировать слот;
- `payments` не должен менять прайс-лист;
- `payments` не должен напрямую подтверждать запись без согласованного бизнес-сценария.

## 5. Термины

### 5.1 Payment
Внутренний агрегат, представляющий платёжную операцию в системе Reva Studio.

### 5.2 Payment Attempt
Попытка провести платёж через провайдера. У одного `Payment` может быть несколько `PaymentAttempt`, если допускаются безопасные повторы.

### 5.3 Payment Intent
Промежуточный внешний объект PSP для подготовки или проведения оплаты. Термин особенно характерен для Stripe API.  
Источник:
- https://docs.stripe.com/api

### 5.4 Idempotency Key
Уникальный ключ, который позволяет безопасно повторить запрос без повторного списания или создания дубликата операции.  
Источник:
- https://docs.stripe.com/api/idempotent_requests

### 5.5 Webhook
Асинхронное HTTP-событие от платёжного провайдера о фактическом изменении статуса внешней транзакции.  
Источники:
- https://docs.stripe.com/webhooks
- https://docs.stripe.com/webhooks/signature

### 5.6 Refund
Операция полного или частичного возврата уже подтверждённого платежа.

### 5.7 Authorization
Подтверждение платёжным провайдером доступности средств без окончательного списания, если конкретный PSP и схема оплаты поддерживают это.

### 5.8 Capture
Финальное списание средств после авторизации, если используется двухшаговая схема.

## 6. Бизнес-сценарии

### 6.1 Полная онлайн-оплата записи
Клиент оплачивает бронь полностью до визита.

### 6.2 Частичная предоплата
Клиент оплачивает только депозит, остальное — офлайн в студии.

### 6.3 Оплата на месте
Система фиксирует платёжное обязательство, но реальное списание онлайн не выполняет.

### 6.4 Возврат
Частичный или полный возврат клиенту после отмены записи или решения оператора.

### 6.5 Неуспешный платёж
Провайдер отклоняет платёж, требует дополнительную аутентификацию или операция истекает.

## 7. Основные проектные решения

Ниже перечислены обязательные внутренние политики Reva Studio.

### 7.1 Источник истины
Источник истины по внешнему состоянию платежа — подтверждённый ответ PSP и webhook-события PSP, а не только client-side redirect.

### 7.2 Идемпотентность обязательна
Все операции создания внешних платёжных действий должны использовать идемпотентность.

### 7.3 Webhook обрабатывается отдельно
Webhook не должен выполнять небезопасную бизнес-логику напрямую в HTTP-request thread; он должен валидироваться, фиксироваться, дедуплицироваться и затем переводиться во внутреннее событие.

### 7.4 Сырые платёжные данные не храним
В домене сохраняются только допустимые метаданные:
- masked brand info при наличии;
- provider customer id;
- provider payment method id/token reference;
- last4 только если это легально и действительно приходит от PSP как безопасный reference field;
- provider charge/payment intent id.

### 7.5 Логи санитизируются
Секреты, токены, подписи и payload с чувствительными полями не должны попадать в обычные application logs.

## 8. Агрегаты и сущности

### 8.1 Aggregate: Payment

Назначение: единая внутренняя сущность денежной операции.

Рекомендуемые поля:

```text
Payment
- id: UUID
- public_id: str
- booking_id: UUID | null
- order_id: UUID | null
- customer_id: UUID
- status: PaymentStatus
- payment_flow: PaymentFlow
- currency: str
- amount_total_minor: int
- amount_discount_minor: int
- amount_bonus_minor: int
- amount_payable_minor: int
- amount_refunded_minor: int
- provider: PaymentProvider
- provider_account_ref: str | null
- provider_payment_intent_id: str | null
- provider_charge_id: str | null
- provider_customer_id: str | null
- payment_method_type: PaymentMethodType | null
- idempotency_key: str
- description: str | null
- metadata_json: jsonb
- created_at: datetime
- updated_at: datetime
- authorized_at: datetime | null
- captured_at: datetime | null
- failed_at: datetime | null
- canceled_at: datetime | null
- refunded_at: datetime | null
- version: int