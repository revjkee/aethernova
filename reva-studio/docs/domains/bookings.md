# Bookings Domain

## Status

Approved for implementation baseline

## Purpose

Домен `bookings` отвечает за полный жизненный цикл записи клиента на услугу в Reva Studio.

Он покрывает:

- создание записи
- проверку доступности слота
- резервирование временного окна
- подтверждение записи
- перенос записи
- отмену записи
- управление статусами визита
- фиксацию факта оказания услуги
- координацию с оплатой, уведомлениями, лояльностью и календарной занятостью
- аудит изменений записи

Этот домен является одним из самых критичных в системе, потому что именно он связывает деньги, расписание, мастеров, клиентов, услуги и фактическую загрузку бизнеса.

---

## Business Goal

Цель домена `bookings`:

- обеспечить корректную и предсказуемую запись клиента
- исключить двойное бронирование одного и того же временного окна
- дать бизнесу управляемую модель расписания
- поддержать ручные и автоматические сценарии записи
- сохранить трассируемость всех изменений
- подготовить модель к multi-tenant масштабу

---

## Domain Scope

Внутри домена `bookings` находятся:

- агрегат записи
- правила доступности слота
- правила пересечений по мастеру и ресурсам
- бизнес-статусы записи
- подтверждение и отмена
- политика переноса
- политика no-show
- фиксация завершения визита
- временные блокировки на время оформления
- аудит критичных изменений
- публикация доменных событий

Вне домена `bookings` остаются:

- управление каталогом услуг
- кадровые данные мастеров
- управление клиентским профилем
- фактическая обработка платежей
- доставка уведомлений
- начисление бонусов и лояльности
- финансовая аналитика
- CRM-маркетинг
- файловые вложения и медиа

---

## Ubiquitous Language

### Booking

Запись клиента на конкретную услугу или набор услуг в заданный временной интервал.

### Booking Slot

Временной интервал, потенциально доступный для бронирования.

### Reservation Hold

Временная мягкая блокировка слота на этапе оформления записи до окончательного подтверждения.

### Appointment

Фактический визит клиента, материализованный из записи.

### Staff Assignment

Назначение конкретного мастера на запись.

### Service Bundle

Набор услуг, входящих в одну запись.

### Booking Source

Источник создания записи. Например:

- client_app
- admin_panel
- staff_panel
- telegram_bot
- internal_operator
- migration
- api_partner

### Booking Status

Текущее бизнес-состояние записи.

### No-Show

Ситуация, когда клиент не пришёл на подтверждённую запись и услуга не была оказана.

### Completion

Факт завершения услуги и закрытия записи как успешно состоявшегося визита.

### Reschedule

Перенос записи на другое время, дату, мастера или набор услуг по допустимым правилам.

---

## Domain Vision

Домен `bookings` должен быть реализован как строго контролируемый transactional core.

Его главные свойства:

- сильные инварианты
- высокая предсказуемость поведения
- минимизация гонок при записи
- ясные статусы
- строгая трассируемость изменений
- совместимость с асинхронными побочными эффектами
- готовность к росту количества салонов и мастеров

---

## Bounded Context Responsibilities

Bounded context `bookings` отвечает за ответы на следующие вопросы:

- можно ли создать запись на данный слот
- не конфликтует ли запись с другими активными записями
- кто назначен на выполнение услуги
- в каком статусе находится запись
- действительна ли запись
- можно ли её подтвердить, перенести или отменить
- считается ли клиент пришедшим
- состоялась ли услуга
- какие доменные события нужно опубликовать после изменения состояния

---

## Domain Invariants

Ниже перечислены обязательные инварианты.

### Invariant 1. No overlapping active bookings for the same staff member

Для одного мастера нельзя иметь две активные записи, пересекающиеся по времени, если обе записи требуют его занятости.

Активными в данном смысле считаются статусы:

- hold
- pending_confirmation
- confirmed
- checked_in
- in_progress

### Invariant 2. Booking must have at least one service item

Запись не может существовать без хотя бы одной выбранной услуги.

### Invariant 3. Booking duration must be deterministic at confirmation time

На момент подтверждения записи длительность должна быть вычислена и зафиксирована.

### Invariant 4. Booking must belong to exactly one tenant

Каждая запись принадлежит только одному tenant.

### Invariant 5. Booking must reference exactly one client identity

Даже если клиент оформляет запись как гость, внутри доменной модели должна существовать единая клиентская идентичность.

### Invariant 6. Confirmed booking must reserve real capacity

Подтверждённая запись обязана занимать реальный слот мастера и, при необходимости, дополнительного ресурса.

### Invariant 7. Completed booking cannot return to active lifecycle

После перехода в `completed` запись не может снова стать `confirmed`, `checked_in` или `in_progress`.

### Invariant 8. Cancelled booking cannot be completed

Отменённая запись не может быть завершена как оказанная услуга.

### Invariant 9. Every critical state transition must be auditable

Каждый критичный переход состояния должен быть зафиксирован в аудите.

### Invariant 10. Status transitions are controlled, not arbitrary

Статус записи меняется только по разрешённому графу переходов.

---

## Subdomains and Internal Concepts

Хотя `bookings` является единым bounded context, внутри него логически выделяются следующие области.

### Scheduling Core

Отвечает за:

- расчет времени начала и окончания
- проверку конфликтов
- резервирование слотов
- правила пересечений

### Booking Lifecycle

Отвечает за:

- статусы записи
- подтверждение
- отмену
- перенос
- завершение
- no-show

### Assignment Rules

Отвечает за:

- назначение мастера
- смену мастера
- проверку допустимости назначения
- зависимость мастера от типа услуги

### Booking Policy Layer

Отвечает за:

- окно предварительной записи
- дедлайны отмены
- дедлайны переноса
- необходимость предоплаты
- необходимость ручного подтверждения

### Audit and Traceability

Отвечает за:

- журнал изменений
- actor tracking
- source tracking
- correlation identifiers

---

## Core Use Cases

### Create Booking

Клиент или сотрудник создаёт новую запись на услугу.

Сценарий включает:

- валидацию tenant
- валидацию клиента
- валидацию услуги
- вычисление длительности
- поиск или валидацию мастера
- проверку доступности
- установку hold или pending_confirmation
- публикацию события `BookingCreated`

### Confirm Booking

Подтверждение записи после ручной проверки, автоматической проверки или после оплаты.

Результат:

- статус становится `confirmed`
- слот считается занятым
- публикуется `BookingConfirmed`

### Reschedule Booking

Перенос существующей записи.

Результат:

- создаётся атомарный переход на новый слот
- старый слот освобождается
- история изменения сохраняется
- публикуется `BookingRescheduled`

### Cancel Booking

Отмена записи клиентом, мастером или администратором.

Результат:

- слот освобождается
- фиксируется причина отмены
- публикуется `BookingCancelled`

### Check In Client

Фиксация прибытия клиента.

Результат:

- статус `checked_in`

### Start Service

Начало фактического оказания услуги.

Результат:

- статус `in_progress`

### Complete Booking

Успешное завершение визита.

Результат:

- статус `completed`
- создаются доменные события для лояльности, аналитики и, при необходимости, финансового закрытия

### Mark No Show

Фиксация неявки клиента.

Результат:

- статус `no_show`
- возможны штрафные или аналитические последствия

---

## Aggregate Design

Главный агрегат домена: `Booking`.

### Aggregate Root: Booking

`Booking` является единственной точкой, через которую должны проходить изменения состояния записи.

### Why Booking is the Aggregate Root

Потому что именно запись является носителем бизнес-инвариантов, связанных с:

- временем
- статусом
- клиентом
- мастером
- услугами
- подтверждением
- отменой
- завершением

---

## Booking Aggregate Structure

### Identity

- booking_id
- tenant_id
- public_booking_number

### Ownership and Source

- client_id
- created_by_actor_id
- created_by_actor_type
- booking_source

### Service Composition

- booking_items
- total_duration_minutes
- service_snapshot_version

### Schedule

- starts_at
- ends_at
- timezone
- booking_date_local

### Assignment

- staff_id
- room_id
- equipment_id

### Lifecycle

- status
- confirmation_required
- confirmed_at
- cancelled_at
- completed_at
- no_show_at

### Commercial Signals

- deposit_required
- deposit_status
- pricing_snapshot
- currency

### Operational Metadata

- comment_for_staff
- comment_for_client
- internal_notes
- reschedule_count
- cancellation_reason
- cancellation_actor_id

### Audit Metadata

- created_at
- updated_at
- version
- correlation_id

---

## Booking Items

Каждая запись должна содержать один или несколько `BookingItem`.

### BookingItem fields

- booking_item_id
- service_id
- service_name_snapshot
- service_duration_minutes_snapshot
- service_price_snapshot
- assigned_staff_id
- position
- quantity

### Booking Item Rules

- item должен ссылаться на услугу через snapshot
- изменение каталога услуг после создания записи не должно ретроактивно ломать уже созданную запись
- duration и price должны фиксироваться snapshot-значениями
- при multi-service записи порядок услуг должен быть явным

---

## Booking Status Model

Поддерживаемые статусы:

- draft
- hold
- pending_confirmation
- confirmed
- checked_in
- in_progress
- completed
- cancelled
- no_show
- expired

---

## Status Definitions

### draft

Черновик записи, ещё не захватывающий полноценный слот.

### hold

Временная блокировка слота на этапе оформления.

### pending_confirmation

Запись создана, но требует подтверждения человеком или бизнес-правилом.

### confirmed

Запись подтверждена и занимает реальную capacity.

### checked_in

Клиент прибыл.

### in_progress

Оказание услуги началось.

### completed

Услуга оказана, визит завершён.

### cancelled

Запись отменена до завершения.

### no_show

Клиент не пришёл, услуга не была оказана.

### expired

Hold истёк, подтверждение не произошло.

---

## Allowed Status Transitions

```text
draft -> hold
draft -> pending_confirmation
hold -> pending_confirmation
hold -> confirmed
hold -> expired
pending_confirmation -> confirmed
pending_confirmation -> cancelled
pending_confirmation -> expired
confirmed -> checked_in
confirmed -> in_progress
confirmed -> cancelled
confirmed -> no_show
checked_in -> in_progress
checked_in -> completed
checked_in -> cancelled
in_progress -> completed