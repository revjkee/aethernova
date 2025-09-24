-- security-core/schemas/sql/migrations/0003_revocation_lists.sql
-- PostgreSQL 13+ (рекомендуется 14/15)
-- Промышленная модель CRL (полные и delta), оптимизированная для высоконагруженных PKI/OCSP.

BEGIN;

-- 1) Техническая схема (опционально держим объекты в 'security')
CREATE SCHEMA IF NOT EXISTS security;

-- 2) Домены и ENUM для причин отзыва (RFC 5280, ReasonFlags)
--    Храним и как ENUM, и как оригинальный код для расширяемости.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'revocation_reason_enum') THEN
    CREATE TYPE security.revocation_reason_enum AS ENUM (
      'unspecified',           -- 0
      'keyCompromise',         -- 1
      'cACompromise',          -- 2
      'affiliationChanged',    -- 3
      'superseded',            -- 4
      'cessationOfOperation',  -- 5
      'certificateHold',       -- 6
      'removeFromCRL',         -- 8
      'privilegeWithdrawn',    -- 9
      'aACompromise'           -- 10
    );
  END IF;
END$$;

-- 3) Хелперы: нормализация серийного номера и хэшей.
--    Серийный может быть произвольной длины: храним как BYTEA, но для индексации полезен SHA256.
CREATE OR REPLACE FUNCTION security.sha256(b bytea)
RETURNS bytea
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT digest(b, 'sha256') FROM pg_catalog.pgcrypto;
$$;

-- Короткий стаб-хэш для HASH партиционирования (int)
CREATE OR REPLACE FUNCTION security.stable_hash32(b bytea)
RETURNS int
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE
  d bytea;
  v int;
BEGIN
  d := digest(b, 'sha256');
  -- Возьмём первые 4 байта как int32 big-endian
  v := (get_byte(d,0) << 24) | (get_byte(d,1) << 16) | (get_byte(d,2) << 8) | get_byte(d,3);
  RETURN v;
END;
$$;

-- 4) Таблица CRL (головная запись). Содержит DER и метаданные.
--    Не привязываемся к внешним таблицам, чтобы миграция была самодостаточной.
CREATE TABLE IF NOT EXISTS security.crl (
  id                    bigserial PRIMARY KEY,

  -- Устойчивые идентификаторы эмитента CRL (для дедупликации и быстрых поисков)
  issuer_dn_hash        bytea        NOT NULL, -- hash(DER Name) или canonicalized; поставляется парсером
  authority_key_id      bytea,                 -- AKI (AuthorityKeyIdentifier.keyIdentifier)
  issuer_spki_sha256    bytea,                 -- SHA-256 от SubjectPublicKeyInfo эмитента (если известен)

  -- Атрибуты CRL по RFC 5280
  crl_number            numeric(39,0),         -- CRLNumber может быть очень большим INTEGER
  is_delta              boolean      NOT NULL DEFAULT false,
  base_crl_number       numeric(39,0),         -- для delta-CRL: BaseCRLNumber

  this_update           timestamptz  NOT NULL,
  next_update           timestamptz,

  -- Алгоритм подписи (OID как текст), параметры (DER) опционально
  signature_algo_oid    text,
  signature_params_der  bytea,

  -- DER-данные: для идеального round-trip и криптопроверок
  tbs_der               bytea        NOT NULL, -- TBSCertList DER
  signature_value       bytea        NOT NULL, -- BIT STRING contents
  signed_der            bytea        NOT NULL, -- полный DER CRL

  -- Дедупликация/идемпотентность загрузки
  signed_der_sha256     bytea        GENERATED ALWAYS AS (security.sha256(signed_der)) STORED,

  -- Источники (AIA/CRL DP URLs и т.п.)
  source_uris           text[],

  -- Служебные поля
  created_at            timestamptz  NOT NULL DEFAULT now(),
  updated_at            timestamptz  NOT NULL DEFAULT now()
);

-- Триггер для updated_at
CREATE OR REPLACE FUNCTION security.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_crl_set_updated_at ON security.crl;
CREATE TRIGGER trg_crl_set_updated_at
BEFORE UPDATE ON security.crl
FOR EACH ROW EXECUTE PROCEDURE security.set_updated_at();

-- Уникальность CRL по эмитенту+номер+тип (delta/полный).
-- Для эмитентов без crlNumber допускаем NULL (тогда уникальность обеспечивается signed_der_sha256).
CREATE UNIQUE INDEX IF NOT EXISTS ux_crl_issuer_num_kind
ON security.crl (issuer_dn_hash, COALESCE(authority_key_id, '\x'::bytea), COALESCE(crl_number, 0::numeric), is_delta);

-- Быстрая дедупликация по DER
CREATE UNIQUE INDEX IF NOT EXISTS ux_crl_der_sha256
ON security.crl (signed_der_sha256);

-- Индексы по идентификаторам эмитента
CREATE INDEX IF NOT EXISTS ix_crl_aki ON security.crl (authority_key_id);
CREATE INDEX IF NOT EXISTS ix_crl_spki ON security.crl (issuer_spki_sha256);
CREATE INDEX IF NOT EXISTS ix_crl_dates ON security.crl (this_update, next_update);

-- 5) Таблица записей отзыва (partitioned HASH по серийному номеру)
--    Храним reason, invalidityDate, поддержку indirect CRL (certificateIssuer).
CREATE TABLE IF NOT EXISTS security.crl_entry (
  id                          bigserial,
  crl_id                      bigint       NOT NULL REFERENCES security.crl(id) ON DELETE CASCADE,

  -- Серийный номера сертификата (как DER INTEGER BYTES) и его хэш
  cert_serial_bytes           bytea        NOT NULL,
  cert_serial_sha256          bytea        GENERATED ALWAYS AS (security.sha256(cert_serial_bytes)) STORED,

  -- Для indirect CRL: issuer сертификата, если отличается от CRL issuer
  certificate_issuer_dn_hash  bytea,       -- может быть NULL, если не indirect
  certificate_aki             bytea,       -- SKI сертификата (если доступно)

  -- Дата отзыва и причина
  revocation_date             timestamptz  NOT NULL,
  reason_enum                 security.revocation_reason_enum,
  reason_code_raw             smallint,    -- оригинальный код ReasonFlags (для расширяемости)
  invalidity_date             timestamptz,

  -- Оригинальные расширения записи (DER → JSONB/DER). Храним в JSONB произвольные поля.
  -- Для строгих систем оставьте NULL и используйте отдельную таблицу для DER «как есть».
  extensions                  jsonb,

  created_at                  timestamptz  NOT NULL DEFAULT now(),

  -- PK отдельный, уникальность обеспечим составным ключом ниже
  PRIMARY KEY (id)
) PARTITION BY HASH (security.stable_hash32(cert_serial_bytes));

-- Создадим 8 партиций (можно изменить оффлайн‑миграцией при росте).
DO $$
DECLARE
  i int;
  part text;
BEGIN
  FOR i IN 0..7 LOOP
    part := format('security.crl_entry_p%1$s', i);
    IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                   WHERE c.relname = part AND n.nspname='security') THEN
      EXECUTE format($$CREATE TABLE security.%I PARTITION OF security.crl_entry
                     FOR VALUES WITH (MODULUS 8, REMAINDER %s);$$, part, i);
      -- Ключевые индексы в каждой партиции
      EXECUTE format('CREATE INDEX ix_%I_crl ON security.%I (crl_id);', part, part);
      EXECUTE format('CREATE INDEX ix_%I_serial_sha256 ON security.%I (cert_serial_sha256);', part, part);
      EXECUTE format('CREATE INDEX ix_%I_revdate ON security.%I (revocation_date);', part, part);
      EXECUTE format('CREATE INDEX ix_%I_reason ON security.%I (reason_enum);', part, part);
      EXECUTE format('CREATE INDEX ix_%I_ci_dn ON security.%I (certificate_issuer_dn_hash);', part, part);
    END IF;
  END LOOP;
END$$;

-- Уникальность: в рамках конкретного CRL не должно быть дубликатов серийных
-- (одна и та же запись в одном CRL встречаться не должна).
-- Так как партиции, делаем индекс в каждой партиции.
DO $$
DECLARE
  r record;
  idx text;
BEGIN
  FOR r IN SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='security' AND relname LIKE 'crl_entry_p%' LOOP
    idx := format('ux_%s_crl_serial', r.relname);
    EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS %I ON security.%I (crl_id, cert_serial_sha256);', idx, r.relname);
  END LOOP;
END$$;

-- 6) Материализованное представление «актуального статуса отзыва».
--    Для высокой скорости ответов OCSP/валидации по (issuer, serial).
--    Логика: берём последние (максимальный this_update) полные CRL по эмитенту
--    и «накатываем» поверх них delta‑CRL с base_crl_number == номеру последнего полного.
--    Примечание: агрегирование упрощено; для сложных кейсов может понадобиться серверная логика.
CREATE MATERIALIZED VIEW IF NOT EXISTS security.current_revocations AS
WITH latest_full AS (
  SELECT DISTINCT ON (issuer_dn_hash, COALESCE(authority_key_id, '\x'::bytea))
         id, issuer_dn_hash, authority_key_id, crl_number, this_update
  FROM security.crl
  WHERE is_delta = false
  ORDER BY issuer_dn_hash, COALESCE(authority_key_id, '\x'::bytea), this_update DESC, crl_number DESC NULLS LAST
),
latest_delta AS (
  SELECT d.*
  FROM security.crl d
  JOIN latest_full f
    ON d.is_delta = true
   AND d.issuer_dn_hash = f.issuer_dn_hash
   AND COALESCE(d.authority_key_id, '\x'::bytea) = COALESCE(f.authority_key_id, '\x'::bytea)
   AND d.base_crl_number = f.crl_number
),
base_entries AS (
  SELECT e.crl_id, c.issuer_dn_hash, COALESCE(c.authority_key_id, '\x'::bytea) AS authority_key_id,
         e.cert_serial_bytes, e.cert_serial_sha256, e.revocation_date, e.reason_enum, e.reason_code_raw, e.invalidity_date
  FROM security.crl_entry e
  JOIN latest_full c ON c.id = e.crl_id
),
delta_entries AS (
  SELECT e.crl_id, c.issuer_dn_hash, COALESCE(c.authority_key_id, '\x'::bytea) AS authority_key_id,
         e.cert_serial_bytes, e.cert_serial_sha256, e.revocation_date, e.reason_enum, e.reason_code_raw, e.invalidity_date
  FROM security.crl_entry e
  JOIN latest_delta c ON c.id = e.crl_id
),
merged AS (
  -- delta может переопределять base: используем последнюю запись по времени отзыва
  SELECT *
  FROM (
    SELECT *, ROW_NUMBER() OVER (
      PARTITION BY issuer_dn_hash, authority_key_id, cert_serial_sha256
      ORDER BY revocation_date DESC
    ) AS rn
    FROM (
      SELECT * FROM base_entries
      UNION ALL
      SELECT * FROM delta_entries
    ) u
  ) z
  WHERE rn = 1
)
SELECT
  issuer_dn_hash,
  authority_key_id,
  cert_serial_bytes,
  cert_serial_sha256,
  revocation_date,
  reason_enum,
  reason_code_raw,
  invalidity_date
FROM merged;

CREATE UNIQUE INDEX IF NOT EXISTS ux_current_rev_issuer_serial
ON security.current_revocations (issuer_dn_hash, authority_key_id, cert_serial_sha256);

CREATE INDEX IF NOT EXISTS ix_current_rev_date
ON security.current_revocations (revocation_date);

-- 7) Полезные представления и функции для выборки статуса по (issuer, serial)

-- Представление для «сырых» записей CRL с привязкой к метаданным CRL
CREATE VIEW IF NOT EXISTS security.crl_entries_expanded AS
SELECT
  e.id,
  e.crl_id,
  c.issuer_dn_hash,
  c.authority_key_id,
  c.is_delta,
  c.crl_number,
  c.this_update,
  c.next_update,
  e.cert_serial_bytes,
  e.cert_serial_sha256,
  e.revocation_date,
  e.reason_enum,
  e.reason_code_raw,
  e.invalidity_date,
  e.certificate_issuer_dn_hash,
  e.certificate_aki
FROM security.crl_entry e
JOIN security.crl c ON c.id = e.crl_id;

-- Функция проверки статуса отзыва (TRUE если отозван)
CREATE OR REPLACE FUNCTION security.is_revoked(
  p_issuer_dn_hash bytea,
  p_authority_key_id bytea,
  p_cert_serial_bytes bytea
) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1
    FROM security.current_revocations r
    WHERE r.issuer_dn_hash = p_issuer_dn_hash
      AND r.authority_key_id = COALESCE(p_authority_key_id, '\x'::bytea)
      AND r.cert_serial_sha256 = security.sha256(p_cert_serial_bytes)
  );
$$;

-- 8) Политики доступа (минимальный пример): чтение для app‑роли, запись — только загрузчику.
-- Применяйте под свою модель ролей.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'security_app') THEN
    CREATE ROLE security_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'security_loader') THEN
    CREATE ROLE security_loader NOLOGIN;
  END IF;
END$$;

GRANT USAGE ON SCHEMA security TO security_app, security_loader;

GRANT SELECT ON security.crl TO security_app;
GRANT SELECT ON ALL TABLES IN SCHEMA security TO security_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON security.crl TO security_loader;
GRANT SELECT, INSERT, UPDATE, DELETE ON security.crl_entry TO security_loader;
GRANT SELECT ON security.current_revocations TO security_loader;
GRANT SELECT ON security.crl_entries_expanded TO security_loader;

-- 9) Начальная REFRESH материализованного представления
REFRESH MATERIALIZED VIEW CONCURRENTLY security.current_revocations;

COMMIT;

-- Примечания по эксплуатации:
-- - Загрузка CRL: вставляйте запись в security.crl, затем батчем вставляйте её записи в security.crl_entry.
-- - После пакетной загрузки: выполните REFRESH MATERIALIZED VIEW CONCURRENTLY security.current_revocations;
-- - Для масштабов >10^9 записей увеличьте число HASH-партиций (онлайн-migration с ATTACH PARTITION).
-- - Для сложной логики с несколькими delta‑CRL поверх base используйте серверную агрегацию/пайплайн перед записью.
