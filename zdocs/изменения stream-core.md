core-systems/csmarket/stream-core/
├── pyproject.toml
├── README.md
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── ruff.toml                      # (+) единый линтер
├── mypy.ini                       # (+) явная типизация
├── pytest.ini                     # (+) настройки тестов
├── .gitignore                     # (+)
├── .dockerignore                  # (+)
├── scripts/
│   ├── dev.ps1
│   ├── dev.sh
│   ├── lint.ps1
│   ├── lint.sh
│   ├── test.ps1
│   ├── test.sh
│   ├── topics.ps1
│   ├── topics.sh                  # (+) Linux аналог
│   ├── produce_sample.ps1         # (+) быстро кинуть событие в raw
│   └── consume.ps1                # (+) быстро посмотреть топик
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── bootstrap.py
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py
│   │   └── logging.yaml           # (+) конфиг логов (опционально)
│   ├── contracts/
│   │   ├── __init__.py
│   │   ├── envelope.py
│   │   ├── steam_raw.py
│   │   ├── steam_normalized.py
│   │   ├── dlq.py
│   │   └── versions/              # (+) версионирование контрактов
│   │       ├── v1/
│   │       │   ├── steam_raw.py
│   │       │   └── steam_normalized.py
│   │       └── __init__.py
│   ├── infra/
│   │   ├── __init__.py
│   │   ├── kafka/
│   │   │   ├── __init__.py
│   │   │   ├── consumer.py
│   │   │   ├── producer.py
│   │   │   ├── admin.py
│   │   │   ├── headers.py
│   │   │   └── serializers.py     # (+) orjson/bytes, единый encode/decode
│   │   ├── db/
│   │   │   ├── __init__.py
│   │   │   ├── engine.py
│   │   │   ├── base.py
│   │   │   ├── models.py
│   │   │   ├── repo.py
│   │   │   └── migrations/        # (+) alembic внутри stream-core (минимум)
│   │   │       ├── alembic.ini
│   │   │       ├── env.py
│   │   │       └── versions/
│   │   │           └── 0001_init_processed_events.py
│   │   ├── redis/
│   │   │   ├── __init__.py
│   │   │   └── client.py
│   │   └── http/
│   │       ├── __init__.py
│   │       └── client.py
│   ├── observability/
│   │   ├── __init__.py
│   │   ├── logging_setup.py
│   │   ├── metrics.py
│   │   ├── tracing.py
│   │   └── health.py              # (+) health endpoints/проверки зависимостей
│   ├── state/
│   │   ├── __init__.py
│   │   ├── dedup.py
│   │   ├── checkpoints.py
│   │   └── state_store.py         # (+) абстракция state (redis/postgres)
│   ├── processors/
│   │   ├── __init__.py
│   │   ├── steam_normalizer.py
│   │   ├── price_aggregator.py
│   │   └── risk_engine.py
│   ├── sinks/
│   │   ├── __init__.py
│   │   ├── postgres_sink.py
│   │   ├── redis_sink.py
│   │   └── dlq_sink.py            # (+) единая запись в DLQ (с причинами)
│   ├── workers/
│   │   ├── __init__.py
│   │   ├── steam_normalizer_worker.py
│   │   ├── price_aggregator_worker.py
│   │   ├── risk_engine_worker.py
│   │   └── telegram_alert_worker.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── ids.py
│   │   ├── json.py
│   │   ├── time.py
│   │   ├── retry.py
│   │   ├── concurrency.py         # (+) семафоры/лимиты/бекпрешер
│   │   └── security.py            # (+) безопасное логирование payload (редакция)
│   └── tests/
│       ├── __init__.py
│       ├── conftest.py
│       ├── test_contracts.py
│       ├── test_dedup.py
│       ├── test_normalizer.py
│       ├── test_kafka_headers.py  # (+)
│       └── e2e/
│           ├── test_pipeline_raw_to_normalized.py  # (+) минимальный e2e
└── infra/
    ├── streaming/
    │   ├── docker-compose.yml
    │   └── redpanda-init/
    │       └── init-topics.sh
    └── schemas/
        ├── steam.market.raw.schema.json
        ├── steam.market.normalized.schema.json
        └── dlq.schema.json         # (+) схема для DLQ событий
