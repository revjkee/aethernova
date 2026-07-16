<!-- human-sovereignty-core/webui/ops/csp_report_endpoint.md -->

# CSP report endpoint (CSP violation reports)

## 1. Цель

CSP violation reports нужны для наблюдаемости и hardening Content-Security-Policy:
- фиксировать попытки inline-script, eval, загрузки скриптов с неразрешённых источников
- выявлять неожиданные подключения (cdn, трекеры, расширения)
- подтверждать, что политика не ломает UI
- иметь артефакты для расследований инцидентов

Endpoint для отчётов является потенциальной точкой злоупотребления, поэтому должен быть:
- максимально простым
- строго валидируемым
- ограниченным по размеру
- ограниченным по частоте
- безопасным по логированию

## 2. Два формата отчётов

Современные браузеры поддерживают два механизма:
1. Report-To (Reporting API, тип отчёта `csp-violation`)
2. report-uri (устаревший, но часто ещё поддерживается)

Рекомендуется включать оба, чтобы покрыть больше клиентов.

## 3. Заголовки CSP для отправки отчётов

### 3.1 Report-To (предпочтительно)

Пример заголовков:

- `Report-To: {"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://YOUR_DOMAIN/api/security/csp-report"}],"include_subdomains":true}`
- `Content-Security-Policy: ...; report-to csp-endpoint;`

Пояснения:
- `group` это имя группы, на которое ссылается `report-to`.
- `max_age` время жизни политики репортинга в секундах.
- endpoint url должен быть HTTPS.
- лучше указывать отдельный путь, не пересекающийся с приложением.

### 3.2 report-uri (fallback)

- `Content-Security-Policy: ...; report-uri https://YOUR_DOMAIN/api/security/csp-report;`

## 4. Минимально безопасная политика CSP для старта

Стартовая политика должна быть достаточно строгой, но не ломать приложение.
В продакшне обычно запрещают inline scripts и eval.

Пример базового шаблона (адаптировать под реальные источники):

Content-Security-Policy:
- default-src 'none';
- base-uri 'self';
- object-src 'none';
- frame-ancestors 'none';
- script-src 'self';
- style-src 'self';
- img-src 'self' data:;
- font-src 'self';
- connect-src 'self' https:;
- media-src 'self';
- worker-src 'self';
- manifest-src 'self';
- form-action 'self';
- upgrade-insecure-requests;
- report-to csp-endpoint;
- report-uri https://YOUR_DOMAIN/api/security/csp-report;

Обязательные пункты безопасности:
- `default-src 'none'` как baseline
- `object-src 'none'` чтобы выключить плагины
- `frame-ancestors 'none'` чтобы запретить clickjacking
- `base-uri 'self'` чтобы исключить подмену base URL

Важно: если у вас Vite/React и вы используете inline style или загружаете с CDN,
политику нужно адаптировать. Нельзя добавлять `unsafe-inline` и `unsafe-eval` без необходимости.

## 5. Endpoint для приёма отчётов

### 5.1 Требования к endpoint

Endpoint должен:
- принимать только POST
- принимать только `application/csp-report` и `application/reports+json` и `application/json`
- ограничивать размер тела (например 16 KB, максимум 64 KB)
- не требовать аутентификации (браузер отправляет сам)
- отвечать быстро (204 No Content)
- не хранить сырой отчёт без фильтрации
- не логировать весь body как есть

### 5.2 Путь

Рекомендуемый путь:
- `/api/security/csp-report`

### 5.3 Что логировать

Логировать только нормализованные поля:
- document-uri (или url)
- blocked-uri
- violated-directive
- effective-directive
- original-policy (опционально, но может быть большой)
- disposition (report/enforce)
- referrer (опционально)
- source-file + line-number + column-number (если есть)

Нельзя логировать:
- полный `script-sample` (может содержать секреты, пользовательские данные)
- любые неизвестные поля без фильтра

## 6. Валидация payload

### 6.1 Reporting API (application/reports+json)

Обычно приходит массив объектов вида:
- type: "csp-violation"
- url: "https://..."
- body: { blockedURL, documentURL, effectiveDirective, violatedDirective, ... }

Минимальная проверка:
- payload должен быть списком длиной 1..N (N ограничить, например 1..20)
- каждый элемент должен иметь type = "csp-violation"
- body должен быть объектом

### 6.2 Legacy csp-report (application/csp-report)

Обычно приходит объект:
- { "csp-report": { ... } }

Минимальная проверка:
- root объект
- ключ "csp-report" существует и является объектом

## 7. Защита endpoint от abuse

### 7.1 Rate limiting

Включить rate limit на уровне edge или API gateway:
- по IP
- по user-agent
- по пути

Пример политики:
- 60 запросов в минуту на IP
- burst 30
- 429 на превышение

### 7.2 Ограничение размера

На уровне сервера:
- лимит тела запроса (например 16 KB)
- early reject 413 Payload Too Large

### 7.3 Отсутствие отражения данных

Endpoint всегда отвечает 204 и не возвращает содержимое.
Не возвращать body отчёта в ответе.

### 7.4 CORS

CSP reports не требуют CORS.
Не включать permissive CORS на этот endpoint.

### 7.5 CSRF

CSRF не актуален для неаутентифицированного endpoint, но:
- endpoint не должен менять состояние
- endpoint не должен связывать отчёт с пользователем по cookie

## 8. Хранилище и ретеншн

Варианты:
- лог-система (лучше всего): structured logs -> SIEM
- отдельная таблица / time-series

Рекомендуемая политика хранения:
- сырые отчёты не хранить
- хранить нормализованные поля
- ретеншн 7-30 дней
- агрегация по blocked-uri и violated-directive

## 9. Метрики для observability

Рекомендуемые метрики:
- csp_reports_total{type="reporting_api|legacy", disposition="report|enforce"}
- csp_reports_by_directive_total{directive="script-src|connect-src|..."}
- csp_reports_blocked_uri_total{blocked_uri="..."} с нормализацией домена
- csp_report_endpoint_rejected_total{reason="too_large|bad_json|unsupported_type"}

## 10. Процесс hardening

1. Включить CSP в режиме отчёта:
   - Content-Security-Policy-Report-Only: ...; report-to ...; report-uri ...
2. Собрать отчёты 3-14 дней
3. Исправить источники и загрузки (CDN, inline, eval)
4. Перевести политику в enforce:
   - Content-Security-Policy: ...
5. Продолжать мониторинг и расследование всплесков

## 11. Проверка корректности

Проверять:
- что браузер действительно отправляет отчёты при нарушениях
- что endpoint отвечает 204
- что отчёты не содержат PII в логах
- что rate limit и size limit работают

## 12. Минимальный чеклист продакшн

- CSP включён хотя бы в Report-Only
- report-to и report-uri настроены
- endpoint POST-only
- лимит тела запроса включён
- rate limiting включён
- нормализация и фильтрация полей включены
- ретеншн задан
- метрики заведены
- алерты на резкие всплески включены
