# steam-integration
# Steam Integration для csmarket

Статус: НЕПОДТВЕРЖДЕНО ПОЛНОСТЬЮ (см. раздел "Недокументированные endpoints Market")

## 1. Цель интеграции

Цель csmarket в части Steam-интеграции:
1) Идентифицировать пользователя Steam на стороне сервера csmarket.
2) Получать базовые метаданные предметов и инвентаря (в рамках доступных официальных интерфейсов Steamworks Web API).
3) Понимать ограничения и комиссии Steam Community Market, чтобы корректно отображать UX и экономику.

Официальная база для Web API интерфейсов Steamworks: ISteamEconomy и ISteamUserAuth. :contentReference[oaicite:0]{index=0}

## 2. Аутентификация пользователя Steam

### 2.1. Серверная проверка session ticket

Для подтверждения Steam-аккаунта пользователя сервер csmarket должен проверять session ticket через `ISteamUserAuth/AuthenticateUserTicket`.

Критично:
1) Этот вызов требует publisher API key.
2) Его нельзя вызывать с клиента; вызывать только с защищенного сервера.

Это прямо указано в Steamworks документации по ISteamUserAuth и в разделе Steamworks "User Authentication and Ownership". :contentReference[oaicite:1]{index=1}

### 2.2. Высокоуровневый поток

Шаги:
1) Клиент получает session ticket (способ получения зависит от типа клиента: native, game integration, либо иной механизм, поддерживаемый вашим клиентом).
2) Клиент отправляет ticket в csmarket backend.
3) Backend вызывает `ISteamUserAuth/AuthenticateUserTicket`.
4) Backend связывает полученный SteamID64 с внутренней учетной записью csmarket.

Подтверждение server-side паттерна: описание в Steamworks "User Authentication and Ownership" и требование вызывать метод только с secure server. :contentReference[oaicite:2]{index=2}

## 3. Экономика и предметы (официальные интерфейсы)

### 3.1. Метаданные предметов через ISteamEconomy

`ISteamEconomy` описан как интерфейс для взаимодействия со Steam Economy, и его следует использовать как один из официальных источников для данных о предметах. :contentReference[oaicite:3]{index=3}

### 3.2. Связь с инвентарной схемой

Документация Steam Inventory Schema указывает, что многие свойства совпадают с теми, что возвращает `ISteamEconomy/GetAssetClassInfo`. :contentReference[oaicite:4]{index=4}

Примечание:
1) Конкретный набор доступных полей и требований зависит от AppID и прав доступа.
2) Любые запросы, требующие publisher key, выполняются только на сервере.

Требование server-side для publisher key подтверждено на примере `ISteamUserAuth` (аналогичный принцип применяется ко всем методам, где требуется ключ). :contentReference[oaicite:5]{index=5}

## 4. Комиссии и правила Steam Community Market

### 4.1. Комиссия/fee на Community Market

Steam Help (Community Market FAQ) указывает, что "buyer pays the Steam Transaction Fee" и что fee рассчитывается и показывается до покупки. :contentReference[oaicite:6]{index=6}

Steam Subscriber Agreement также подтверждает, что Valve может взимать fee за транзакции в Subscription Marketplace и что fees раскрываются до завершения транзакции. :contentReference[oaicite:7]{index=7}

Практический вывод для csmarket:
1) В интерфейсе csmarket нельзя обещать пользователю фиксированную комиссию Steam; корректно показывать, что Steam fee отображается перед подтверждением покупки внутри Steam.
2) Экономическая модель csmarket должна учитывать, что Steam может взимать комиссию, и пользователь увидит ее на подтверждении. :contentReference[oaicite:8]{index=8}

## 5. Недокументированные endpoints Market (НЕ МОГУ ПОДТВЕРДИТЬ)

В сообществе часто используют endpoint `priceoverview` для получения цены предмета на Steam Community Market, но Valve не предоставляет официальной публичной документации Steamworks на этот endpoint.

Я не могу подтвердить, что это официально поддерживаемый API Valve.

Наблюдаемая в сообществе информация:
1) StackOverflow обсуждает `priceoverview` как способ получить цену по `appid` и `market_hash_name`. :contentReference[oaicite:9]{index=9}
2) Существуют сторонние библиотеки, которые оборачивают Steam Community Market endpoints, но это не является подтверждением официальной поддержки Valve. :contentReference[oaicite:10]{index=10}

Если csmarket использует такие endpoints:
1) Нужно считать их "best-effort" и закладывать отказоустойчивость.
2) Нельзя гарантировать SLA и стабильность формата ответов.
3) Нужно соблюдать требования Steam Subscriber Agreement и правила платформы, включая ограничения по автоматизации.

Основание про отсутствие официальной документации на Market API в открытом виде встречается в обсуждениях сообщества; как официальный факт Valve это не подтверждает. :contentReference[oaicite:11]{index=11}

## 6. Минимальные требования безопасности для csmarket

1) Все ключи (Steam Web API Key, Publisher Key) хранятся только на сервере и не попадают в клиент.
2) Вызовы методов, требующих publisher key (например `AuthenticateUserTicket`), выполняются только из backend.
3) Логи, метрики и аудит должны исключать утечки токенов/ключей.

Требование "никогда не использовать этот API метод напрямую из клиентов" подтверждено для `AuthenticateUserTicket`. :contentReference[oaicite:12]{index=12}

## 7. Рекомендуемые сущности данных (в терминах csmarket)

1) SteamIdentity:
- steamid64
- verified_at
- auth_method (ticket)
- last_seen_at

2) SteamItemRef:
- appid
- classid
- instanceid
- market_hash_name (если применимо)

3) SteamMarketSnapshot (если вы используете недокументированные endpoints, статус НЕПОДТВЕРЖДЕНО):
- currency
- lowest_price
- median_price
- volume
- fetched_at
- source (community endpoint)

Факт доступности конкретных полей для Market snapshot я не могу подтвердить как официальную спецификацию Valve; это зависит от недокументированных ответов. :contentReference[oaicite:13]{index=13}
