# ChronoWatch Core

Единый сервис времени, расписаний и распределенных лиз во всей платформе (NeuroCity / Aethernova). Поставляет согласованное «истинное» время, управляет cron/interval расписаниями, генерирует события и выдает лизы для координации распределенных процессов.

## Ключевые свойства

- Согласованное время:
  - Источник — системные стеночные часы (UTC) под управлением chrony/ntpd на узлах.
  - Контроль дрейфа, экспонирование `wall_time` и `monotonic_time`.
  - Поддержка логических часов (Lamport/Hybrid Logical Clock) для причинной упорядоченности.
- Расписания:
  - Типы: CRON, fixed-rate, fixed-delay, ISO8601 duration.
  - SLA на доставку триггера, дедупликация и backpressure.
  - Идемпотентность исполнения с журналом.
- Распределенные лизы:
  - Fair lease + TTL + авто-продление.
  - Fencing tokens для защиты от split-brain.
- API: gRPC и REST (стабильные контракты, версионирование v1).
- Наблюдаемость: Prometheus метрики, OpenTelemetry трейсинг, структурные логи.
- Безопасность: mTLS, JWT (OIDC), опционально OPA (Rego) для политик.
- Хранилище: PostgreSQL (рекомендовано), совместимо с CockroachDB/Cloud Spanner* (*нужно валидационное тестирование).
- Масштабирование: горизонтальное; лидерство через lease; шардирование расписаний по ключу.

> Примечание: поддержка «високосных секунд» зависит от ОС/chrony. На уровне приложения фиксируем фактическое системное время и не моделируем leap seconds в пользовательском API.

---

## Архитектура (высокоуровнево)

```
          +---------------------+
          |  Clients / Services |
          +----------+----------+
                     | gRPC/REST
             +-------v--------+
             | chronowatch    |   <- этот проект
             |  API Gateway   |
             +---+---------+--+
                 |         |
       +---------v-+   +---v-----------+
       | Time svc  |   | Scheduler svc |
       +---------+-+   +---+-----------+
                 |         |
           +-----v-+   +--v----+
           | Lease |   | Event |
           |  svc  |   | Bus   |
           +---+---+   +--+----+
               |          |
          +----v----+  +--v------------------+
          | Postgres|  | Kafka/NATS/RabbitMQ |
          +---------+  +---------------------+
```

- **Time svc**: выдача согласованного времени, HLC, контроль дрейфа.
- **Scheduler svc**: хранение расписаний, планирование, доставка триггеров.
- **Lease svc**: выдача/продление/освобождение лиз с fencing.
- **Event Bus**: публикация событий расписаний (subject/topic configurable).

---

## Доменные сущности

- `ClockReading`: { `wall_unix_nanos`, `monotonic_nanos`, `hlc_physical_nanos`, `hlc_logical`, `tz`, `clock_id` }.
- `Schedule`: { `id`, `type`(CRON|RATE|DELAY|ISO8601), `expr`, `payload`, `enabled`, `owner`, `sla_ms`, `retry_policy`, `next_run`, `shard_key`, `created_at`, `updated_at` }.
- `Execution`: { `id`, `schedule_id`, `firing_time`, `delivery_state`, `attempt`, `trace_id` }.
- `Lease`: { `name`, `holder_id`, `fencing_token`, `ttl_ms`, `acquired_at`, `renewed_at` }.

---

## API контракты

### Protobuf (gRPC, v1)

```proto
syntax = "proto3";
package chronowatch.v1;

message NowRequest {}
message NowResponse {
  int64 wall_unix_nanos = 1;
  int64 monotonic_nanos = 2;
  string tz = 3;
  string iso8601 = 4;
  string clock_id = 5;
  int64 hlc_physical_nanos = 6;
  int64 hlc_logical = 7;
}

message CreateScheduleRequest {
  string type = 1;      // CRON|RATE|DELAY|ISO8601
  string expr = 2;      // "*/5 * * * *" | "rate:5s" | "delay:30s" | "PT5M"
  bytes payload = 3;
  bool enabled = 4;
  string owner = 5;
  int32 sla_ms = 6;
  string shard_key = 7;
}
message ScheduleId { string id = 1; }
message Schedule { string id = 1; string type = 2; string expr = 3; bool enabled = 4; string owner = 5; int64 next_run_unix_ms = 6; int32 sla_ms = 7; string shard_key = 8; }
message ListSchedulesRequest { int32 limit = 1; string page_token = 2; }
message ListSchedulesResponse { repeated Schedule items = 1; string next_page_token = 2; }

message AcquireLeaseRequest { string name = 1; string holder_id = 2; int32 ttl_ms = 3; }
message AcquireLeaseResponse { bool acquired = 1; int64 fencing_token = 2; int64 expires_at_unix_ms = 3; }
message RenewLeaseRequest { string name = 1; string holder_id = 2; int32 ttl_ms = 3; int64 fencing_token = 4; }
message ReleaseLeaseRequest { string name = 1; string holder_id = 2; int64 fencing_token = 3; }

service TimeService {
  rpc Now (NowRequest) returns (NowResponse);
}

service ScheduleService {
  rpc Create (CreateScheduleRequest) returns (ScheduleId);
  rpc Get (ScheduleId) returns (Schedule);
  rpc List (ListSchedulesRequest) returns (ListSchedulesResponse);
  rpc Pause (ScheduleId) returns (Schedule);
  rpc Resume (ScheduleId) returns (Schedule);
  rpc Delete (ScheduleId) returns (ScheduleId);
}

service LeaseService {
  rpc Acquire (AcquireLeaseRequest) returns (AcquireLeaseResponse);
  rpc Renew (RenewLeaseRequest) returns (AcquireLeaseResponse);
  rpc Release (ReleaseLeaseRequest) returns (ScheduleId);
}
```

### REST (OpenAPI фрагмент)

- `GET  /api/v1/time/now`
- `POST /api/v1/schedules`
- `GET  /api/v1/schedules/{id}`
- `GET  /api/v1/schedules?limit=&page_token=`
- `POST /api/v1/schedules/{id}:pause`
- `POST /api/v1/schedules/{id}:resume`
- `DELETE /api/v1/schedules/{id}`
- `POST /api/v1/leases:acquire`
- `POST /api/v1/leases:renew`
- `POST /api/v1/leases:release`

Все ответы JSON; trace-id в заголовке `traceparent` (W3C).

---

## Конфигурация

```yaml
# file: config/chronowatch.yaml
server:
  http_addr: 0.0.0.0:8080
  grpc_addr: 0.0.0.0:9090
  read_timeout_ms: 5000
  write_timeout_ms: 5000
security:
  mtls_enabled: true
  ca_cert_path: /etc/chronowatch/pki/ca.pem
  server_cert_path: /etc/chronowatch/pki/server.pem
  server_key_path: /etc/chronowatch/pki/server.key
  jwt_issuer: https://auth.local/
  jwt_audience: chronowatch
  opa_policy_path: /etc/chronowatch/policy.rego
time:
  timezone: Europe/Stockholm
  max_drift_ms: 20
scheduler:
  default_sla_ms: 1000
  shards: 16
  event_bus: kafka
  event_topic: chronowatch.firings.v1
db:
  dsn: postgresql+asyncpg://user:pass@postgres:5432/chronowatch
observability:
  prometheus_path: /metrics
  otlp_endpoint: http://otel-collector:4317
  log_level: info
```

ENV override (пример):
```
CHRONO_TZ=Europe/Stockholm
CHRONO_DB_DSN=postgresql+asyncpg://user:pass@postgres:5432/chronowatch
```

---

## Модель данных (SQLAlchemy async, Python)

```python
# file: app/models.py
from datetime import datetime
from sqlalchemy.orm import declarative_base, Mapped, mapped_column
from sqlalchemy import String, Boolean, Integer, BigInteger, LargeBinary
Base = declarative_base()

class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    type: Mapped[str] = mapped_column(String(16), index=True)    # CRON|RATE|DELAY|ISO8601
    expr: Mapped[str] = mapped_column(String(128))
    payload: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    owner: Mapped[str] = mapped_column(String(128), index=True)
    sla_ms: Mapped[int] = mapped_column(Integer, default=1000)
    shard_key: Mapped[str] = mapped_column(String(64), index=True)
    next_run_unix_ms: Mapped[int] = mapped_column(BigInteger, index=True)
    created_at: Mapped[int] = mapped_column(BigInteger, default=lambda: int(datetime.utcnow().timestamp()*1000))
    updated_at: Mapped[int] = mapped_column(BigInteger, default=lambda: int(datetime.utcnow().timestamp()*1000))

class Lease(Base):
    __tablename__ = "leases"
    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    holder_id: Mapped[str] = mapped_column(String(128), index=True)
    fencing_token: Mapped[int] = mapped_column(BigInteger, index=True)
    ttl_ms: Mapped[int] = mapped_column(Integer)
    acquired_at_unix_ms: Mapped[int] = mapped_column(BigInteger, index=True)
    renewed_at_unix_ms: Mapped[int] = mapped_column(BigInteger, index=True)
```

---

## Эталонная служба (Python, FastAPI + async)

```python
# file: app/main.py
import os, time, uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select
from app.models import Base, Schedule, Lease

TZ = os.getenv("CHRONO_TZ", "Europe/Stockholm")
engine = create_async_engine(os.getenv("CHRONO_DB_DSN", "postgresql+asyncpg://user:pass@localhost:5432/chronowatch"))
Session = async_sessionmaker(engine, expire_on_commit=False)
app = FastAPI(title="chronowatch-core")

class NowDTO(BaseModel):
    wall_unix_nanos: int
    monotonic_nanos: int
    tz: str
    iso8601: str
    clock_id: str
    hlc_physical_nanos: int
    hlc_logical: int

@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.get("/api/v1/time/now", response_model=NowDTO)
async def now():
    wall_ns = time.time_ns()
    mono_ns = time.monotonic_ns()
    iso = datetime.now(ZoneInfo(TZ)).isoformat()
    # Простейший HLC: физическое время + логическая компонента = 0 для single-node примера
    return NowDTO(
        wall_unix_nanos=wall_ns,
        monotonic_nanos=mono_ns,
        tz=TZ,
        iso8601=iso,
        clock_id=str(uuid.uuid4()),
        hlc_physical_nanos=wall_ns,
        hlc_logical=0,
    )

class CreateScheduleDTO(BaseModel):
    type: str
    expr: str
    payload: str | None = None
    enabled: bool = True
    owner: str
    sla_ms: int = 1000
    shard_key: str

class ScheduleDTO(BaseModel):
    id: str
    type: str
    expr: str
    enabled: bool
    owner: str
    sla_ms: int
    shard_key: str
    next_run_unix_ms: int

@app.post("/api/v1/schedules", response_model=dict)
async def create_schedule(req: CreateScheduleDTO):
    # TODO: валидация expr (croniter/iso8601), расчет next_run_unix_ms
    sid = uuid.uuid7().hex[:26] if hasattr(uuid, "uuid7") else uuid.uuid4().hex[:26]
    next_ms = int(datetime.now(timezone.utc).timestamp() * 1000)  # placeholder
    async with Session() as session:
        s = Schedule(
            id=sid, type=req.type, expr=req.expr,
            payload=(req.payload.encode() if req.payload else None),
            enabled=req.enabled, owner=req.owner, sla_ms=req.sla_ms,
            shard_key=req.shard_key, next_run_unix_ms=next_ms
        )
        session.add(s)
        await session.commit()
    return {"id": sid}

@app.get("/api/v1/schedules/{sid}", response_model=ScheduleDTO)
async def get_schedule(sid: str):
    async with Session() as session:
        res = await session.execute(select(Schedule).where(Schedule.id == sid))
        s = res.scalar_one_or_none()
        if not s:
            raise HTTPException(404, "not found")
        return ScheduleDTO(
            id=s.id, type=s.type, expr=s.expr, enabled=s.enabled,
            owner=s.owner, sla_ms=s.sla_ms, shard_key=s.shard_key,
            next_run_unix_ms=s.next_run_unix_ms
        )
```

> Замечание: в продакшене добавьте валидацию CRON (croniter), планировщик (APScheduler/собственный), воркеры доставки, идемпотентность и дедупликацию.

---

## Наблюдаемость

Prometheus метрики (минимальный набор):
- `chronowatch_time_now_latency_ms` (histogram)
- `chronowatch_schedules_total` (gauge, labels: type, enabled)
- `chronowatch_schedule_fire_total` (counter, labels: type, shard)
- `chronowatch_lease_acquire_total` (counter, labels: result)
- `chronowatch_lease_held_gauge` (gauge, labels: name)

OpenTelemetry:
- Экспорт трейсов в OTLP (`observability.otlp_endpoint`), контекст по W3C Trace Context.

Логи:
- Структурные JSON-логи; поля: `ts`, `level`, `msg`, `trace_id`, `span_id`, `schedule_id`, `lease_name`.

---

## Безопасность

- mTLS для gRPC и REST (ingress termination + pod-to-pod).
- JWT проверка: issuer, audience, exp/nbf; маппинг ролей в политики.
- OPA (необязательно): проверка `CreateSchedule`, `AcquireLease` по Rego.
- Защита от дрейфа времени: алерты при `|wall - monotonic| > max_drift_ms`.

---

## Тестирование

- Unit: валидация cron/iso8601, SLA, идемпотентность.
- Property-based: генерация случайных расписаний и проверка монотонности `next_run`.
- Chaos: задержки в БД/шине, рестарты лидера, fence-токены.
- Нагрузка: p95/p99 latency на `Now` и `Create`.

Пример pytest (упрощенно):
```python
# file: tests/test_now.py
from httpx import AsyncClient
from app.main import app

async def test_now_endpoint():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        r = await ac.get("/api/v1/time/now")
        assert r.status_code == 200
        j = r.json()
        assert "wall_unix_nanos" in j and j["wall_unix_nanos"] > 0
        assert "iso8601" in j and "T" in j["iso8601"]
```

---

## Развертывание

### Docker Compose (фрагмент)

```yaml
version: "3.9"
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: chronowatch
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    ports: ["5432:5432"]
  chronowatch:
    build: .
    environment:
      CHRONO_DB_DSN: postgresql+asyncpg://user:pass@postgres:5432/chronowatch
      CHRONO_TZ: Europe/Stockholm
    ports:
      - "8080:8080"
      - "9090:9090"
    depends_on: [postgres]
```

### Helm values (фрагмент)

```yaml
image:
  repository: registry.local/chronowatch
  tag: v1.0.0
service:
  httpPort: 8080
  grpcPort: 9090
resources:
  limits: { cpu: "1", memory: "1Gi" }
  requests: { cpu: "200m", memory: "256Mi" }
env:
  CHRONO_TZ: Europe/Stockholm
  CHRONO_DB_DSN: postgresql+asyncpg://user:pass@postgres:5432/chronowatch
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: chronowatch.local
      paths:
        - path: /
          pathType: Prefix
```

---

## SLO/SLA

- SLO p95 `GET /time/now` < 10 ms при локальной сети.
- SLO планировщика: ошибка доставки триггера < 0.1%/сутки.
- Доступность сервиса за месяц: >= 99.9% (исключая плановые окна).

---

## Дорожная карта

- [ ] Полный HLC (физическое+логическое) с кворум-обновлением.
- [ ] Шардированный планировщик с динамическим ребалансом.
- [ ] История исполнений и replayer.
- [ ] Политики OPA на операции расписаний/лиз.
- [ ] Экспортер метрик резерва по времени и дрейфа.

---

## Лицензия

MIT — см. файл `LICENSE`.
