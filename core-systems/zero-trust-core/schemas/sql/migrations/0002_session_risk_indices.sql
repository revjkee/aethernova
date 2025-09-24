-- zero-trust-core/schemas/sql/migrations/0002_session_risk_indices.sql
-- Purpose: Индексы и ограничения для быстрых risk/MFA решений в ZTNA.
-- Target:  PostgreSQL 12+ (поддержка INCLUDE, GENERATED уже не требуется — используем функциональные индексы).
-- Notes:   CREATE INDEX IF NOT EXISTS безопасен при повторном прогоне.

-- 1) Безопасные лимиты блокировок для DDL
SET lock_timeout = '5s';
SET statement_timeout = '5min';

-- 2) Базовые проверки на диапазоны TTL (NOT VALID -> VALIDATE, чтобы не держать долгие блокировки на больших таблицах)
ALTER TABLE ztc.session_risk
  ADD CONSTRAINT session_risk_ttl_range_chk
  CHECK (ttl_seconds BETWEEN 1 AND 86400) NOT VALID;

ALTER TABLE ztc.session_risk VALIDATE CONSTRAINT session_risk_ttl_range_chk;

-- 3) Функциональные/частичные индексы под hot-пути

-- 3.1 Активные сейчас записи (по TTL): computed_at + ttl_seconds > now()
-- Частичный индекс покрывает только живые решения — идеально для real-time «is session allowed?»
CREATE INDEX IF NOT EXISTS ix_session_risk_active_ttl
ON ztc.session_risk
USING btree ( (computed_at + make_interval(secs => ttl_seconds)) )
INCLUDE (session_id, user_id, tenant, decision, risk_score)
WHERE (computed_at + make_interval(secs => ttl_seconds)) > now();

-- 3.2 Последние решения по пользователю в рамках арендатора
-- Составной индекс для запроса вида: WHERE tenant=$1 AND user_id=$2 ORDER BY computed_at DESC LIMIT 1
CREATE INDEX IF NOT EXISTS ix_session_risk_user_recent
ON ztc.session_risk
USING btree (tenant, user_id, computed_at DESC)
INCLUDE (session_id, decision, risk_score);

-- 3.3 Последние решения по сессии (быстрый джойн по session_id)
CREATE INDEX IF NOT EXISTS ix_session_risk_session_recent
ON ztc.session_risk
USING btree (session_id, computed_at DESC)
INCLUDE (tenant, user_id, decision, risk_score);

-- 3.4 Быстрый поиск эскалаций/блокировок за последние N минут
-- decision: 1=ALLOW, 2=STEP_UP, 3=DENY (или маппинг вашего enum'а) — используйте соответствующие значения вашего типа
CREATE INDEX IF NOT EXISTS ix_session_risk_decision_recent
ON ztc.session_risk
USING btree (decision, computed_at DESC)
INCLUDE (tenant, user_id, session_id, risk_score)
WHERE decision IN (2, 3);

-- 3.5 Выборка «высокий риск» с приоритетом по свежести
CREATE INDEX IF NOT EXISTS ix_session_risk_highscore_recent
ON ztc.session_risk
USING btree (risk_score DESC, computed_at DESC)
INCLUDE (tenant, user_id, session_id)
WHERE risk_score >= 80;

-- 4) Навигация по времени и атрибутам

-- 4.1 BRIN по времени для диапазонных сканов (аналитика, отчёты, ретеншн)
-- BRIN крайне дешёв и эффективен на монотонных по времени вставках.
CREATE INDEX IF NOT EXISTS ix_session_risk_computed_at_brin
ON ztc.session_risk
USING brin (computed_at) WITH (pages_per_range = 64);

-- 4.2 GIN по JSONB-атрибутам (быстрые точечные/путевые запросы по сигналам)
-- Пример запросов: attributes @> '{"country":"SE"}' или jsonb_path_query(...)
CREATE INDEX IF NOT EXISTS ix_session_risk_attributes_gin
ON ztc.session_risk
USING gin (attributes jsonb_path_ops);

-- 5) Сетевой контекст: IP/ASN/страна

-- 5.1 Индекс по IP (равенство/сортировка); для сетевых предикатов может потребоваться GiST/inet_ops — добавьте при необходимости.
CREATE INDEX IF NOT EXISTS ix_session_risk_ip
ON ztc.session_risk
USING btree (ip);

-- 5.2 Индекс по ASN
CREATE INDEX IF NOT EXISTS ix_session_risk_asn
ON ztc.session_risk
USING btree (asn);

-- 5.3 Индекс по стране (ISO-2)
CREATE INDEX IF NOT EXISTS ix_session_risk_country
ON ztc.session_risk
USING btree (country);

-- 6) Комбинированный индекс для «активных deny/step_up» по арендатору (для дешёвых дашбордов/алертов)
CREATE INDEX IF NOT EXISTS ix_session_risk_active_enforced_tenant
ON ztc.session_risk
USING btree (tenant, decision, (computed_at + make_interval(secs => ttl_seconds)) DESC)
INCLUDE (user_id, session_id, risk_score)
WHERE decision IN (2, 3)  -- STEP_UP, DENY
  AND (computed_at + make_interval(secs => ttl_seconds)) > now();

-- 7) Комментарии для само-документации (упрощают эксплуатацию)
COMMENT ON INDEX ix_session_risk_active_ttl IS
'Активные (по TTL) решения risk/MFA; функциональный частичный индекс';
COMMENT ON INDEX ix_session_risk_user_recent IS
'Последнее решение по пользователю в рамках арендатора';
COMMENT ON INDEX ix_session_risk_session_recent IS
'Последние решения по конкретной сессии';
COMMENT ON INDEX ix_session_risk_decision_recent IS
'Быстрый поиск step_up/deny по свежести';
COMMENT ON INDEX ix_session_risk_highscore_recent IS
'Свежие записи с высоким risk_score (>=80)';
COMMENT ON INDEX ix_session_risk_computed_at_brin IS
'BRIN по времени вычисления решения для аналитики';
COMMENT ON INDEX ix_session_risk_attributes_gin IS
'GIN по JSONB атрибутам (сигналы/метаданные)';
COMMENT ON INDEX ix_session_risk_ip IS
'BTREE по IP для равенства/сортировки';
COMMENT ON INDEX ix_session_risk_asn IS
'BTREE по ASN';
COMMENT ON INDEX ix_session_risk_country IS
'BTREE по ISO-стране';
COMMENT ON INDEX ix_session_risk_active_enforced_tenant IS
'Активные step_up/deny по арендатору, отсортированы по актуальности';

-- Конец миграции
