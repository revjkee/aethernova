# 0002-telegram-auth-initdata
# ADR 0002: Telegram auth via initData validation

Status: Accepted
Date: 2026-02-13
Context: csmarket Telegram Mini App

## Context

Telegram Mini Apps передают данные запуска в поле initData, которое предназначено для серверной валидации. Клиентское представление initDataUnsafe не является доверенным источником и не должно использоваться для аутентификации или авторизации без серверной проверки. :contentReference[oaicite:0]{index=0}

В нашем проекте требуется промышленная схема аутентификации пользователя Mini App без отдельной регистрации в Telegram UI, но с серверным доверием только к данным, подписанным Telegram. Требование сервера валидировать initData перед использованием прямо указано в документации Telegram. :contentReference[oaicite:1]{index=1}

## Decision

Мы принимаем стандарт:
1. Клиент (Mini App) передаёт на backend исключительно raw строку initData.
2. Backend валидирует подпись initData по алгоритму Telegram и отвергает запрос при несовпадении hash.
3. Backend применяет TTL к auth_date для защиты от replay.
4. Backend никогда не использует initDataUnsafe для доверенных решений.
5. Идентичность пользователя в csmarket основывается на user.id из валидированного initData.

Основание: Telegram указывает, что данные из initDataUnsafe не должны считаться доверенными, а initData должен быть проверен на сервере. :contentReference[oaicite:2]{index=2}

## Validation algorithm (normative)

Backend реализует проверку целостности данных, полученных из initData, по схеме Telegram:
1. Распарсить initData как query string.
2. Удалить параметр hash из набора пар.
3. Сформировать data check string как строки key=value, отсортированные по ключу в алфавитном порядке, разделитель строк LF.
4. Вычислить secret key на основе bot token и константы WebAppData через HMAC-SHA256.
5. Вычислить HMAC-SHA256 от data check string с использованием secret key и сравнить с hash из initData.

Данный порядок и смысл проверки описаны в официальной документации Telegram по Web Apps и в инженерной документации по init data. :contentReference[oaicite:3]{index=3}

## TTL and replay protection (normative)

Backend обязан проверять auth_date и отклонять initData, если оно старше допустимого TTL.
TTL задаётся конфигурацией (например, 300 секунд для интерактивных сессий, больше для редких сценариев), но всегда должен применяться, так как initData является фактором аутентификации, и его безопасность критична. :contentReference[oaicite:4]{index=4}

## Transport and storage rules (normative)

1. initData передаётся с клиента на сервер только по HTTPS.
2. initData и bot token не логируются целиком. Разрешено логировать минимальный набор: user.id, auth_date, request_id, результат проверки.
3. Bot token хранится только в секрет-хранилище или переменных окружения, не коммитится в репозиторий.

Документация Telegram подчёркивает необходимость серверной проверки и недоверия к initDataUnsafe, что требует минимизации поверхности утечек и корректного доверия. :contentReference[oaicite:5]{index=5}

## Error handling (normative)

Backend возвращает:
1. 401 Unauthorized при невалидном hash или отсутствии обязательных полей.
2. 401 Unauthorized при истёкшем TTL.
3. 400 Bad Request при некорректном формате initData.

## Implementation notes (non-normative)

Если используется aiogram, допустимо применять встроенную утилиту безопасного парсинга и валидации initData на сервере, которая валидирует данные и выбрасывает ошибку при невалидности. :contentReference[oaicite:6]{index=6}

## Consequences

Плюсы:
1. Сервер доверяет только данным, подписанным Telegram.
2. Унифицируется аутентификация для всех Mini App клиентов.
3. Снижается риск подделки user и параметров запуска.

Минусы:
1. Требуется строгая серверная реализация и контроль TTL.
2. Любые расхождения в канонизации строки могут привести к отказу валидации.

## References

1. Telegram Bot API Web Apps: initData и предупреждение о необходимости валидации на сервере. :contentReference[oaicite:7]{index=7}
2. Telegram Mini Apps docs: init data как фактор аутентификации и требования к безопасности. :contentReference[oaicite:8]{index=8}
3. aiogram utils: safe_parse_webapp_init_data для серверной валидации. :contentReference[oaicite:9]{index=9}
