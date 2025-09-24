# physical_integration/registry/repository.py
# Асинхронный промышленный репозиторий для реестра устройств (PostgreSQL + SQLAlchemy 2.x)
from __future__ import annotations

import re
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncConnection, create_async_engine

# Доменные исключения

class RepositoryError(RuntimeError):
    pass

class NotFoundError(RepositoryError):
    pass

class ConflictError(RepositoryError):
    pass

# Конфигурация репозитория

@dataclass(frozen=True)
class RegistryConfig:
    dsn: str                                   # пример: postgresql+asyncpg://user:pass@host:5432/db
    pool_size: int = 10
    max_overflow: int = 0
    pool_pre_ping: bool = True
    echo: bool = False
    schema_search_path: str = "physical_registry,public"
    statement_timeout_ms: int = 5000           # guardrail, может переопределяться на методах
    application_name: str = "pic-registry-repo"

class PgRegistryRepository:
    """
    Репозиторий поверх схемы physical_registry (см. миграцию 0001_init_device_registry.sql).
    Использует RLS и требует на каждом запросе SET LOCAL app.tenant_id = '<uuid>'.
    """

    def __init__(self, cfg: RegistryConfig) -> None:
        self.cfg = cfg
        self.engine: AsyncEngine = create_async_engine(
            cfg.dsn,
            echo=cfg.echo,
            pool_size=cfg.pool_size,
            max_overflow=cfg.max_overflow,
            pool_pre_ping=cfg.pool_pre_ping,
            connect_args={"server_settings": {"application_name": cfg.application_name}},
        )
        self._search_path_sql = self._build_search_path_sql(cfg.schema_search_path)

    @staticmethod
    def _build_search_path_sql(search_path: str) -> str:
        """
        Безопасно формирует команду SET LOCAL search_path. Запрещаем любые символы, кроме a-z0-9_ и запятой.
        """
        if not re.fullmatch(r"[a-zA-Z0-9_, ]{1,256}", search_path or ""):
            raise ValueError("Invalid search_path")
        # Нельзя биндингом подставлять search_path; инлайним прошедшее валидацию значение как идентификаторы.
        parts = [p.strip() for p in search_path.split(",") if p.strip()]
        quoted = ", ".join(parts)
        return f"SET LOCAL search_path = {quoted}"

    async def close(self) -> None:
        await self.engine.dispose()

    # ---- Внутренние контексты ------------------------------------------------

    @asynccontextmanager
    async def _conn(self) -> AsyncIterator[AsyncConnection]:
        async with self.engine.begin() as conn:
            yield conn

    async def _prepare_session(
        self,
        conn: AsyncConnection,
        tenant_id: Optional[str],
        statement_timeout_ms: Optional[int] = None,
    ) -> None:
        await conn.execute(text(self._search_path_sql))
        if statement_timeout_ms is None:
            statement_timeout_ms = self.cfg.statement_timeout_ms
        await conn.execute(text(f"SET LOCAL statement_timeout = {int(statement_timeout_ms)}"))
        if tenant_id:
            await conn.execute(text("SET LOCAL app.tenant_id = :tid"), {"tid": tenant_id})

    # ---- Health ----------------------------------------------------------------

    async def health(self) -> Dict[str, Any]:
        try:
            async with self._conn() as c:
                await self._prepare_session(c, tenant_id=None, statement_timeout_ms=1000)
                row = (await c.execute(text("SELECT 1 AS ok"))).mappings().one()
                return {"ok": bool(row["ok"] == 1)}
        except Exception as e:
            raise RepositoryError(f"health check failed: {e}") from e

    # ---- TENANTS ---------------------------------------------------------------

    async def get_tenant_id_by_name(self, name: str) -> str:
        sql = text("SELECT id FROM physical_registry.tenants WHERE name = :name AND status <> 'deleted'")
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=None)
            row = (await c.execute(sql, {"name": name})).scalar_one_or_none()
            if not row:
                raise NotFoundError("tenant not found")
            return str(row)

    # ---- MANUFACTURERS & MODELS -----------------------------------------------

    async def upsert_manufacturer(self, name: str, country: Optional[str] = None, website: Optional[str] = None) -> Dict[str, Any]:
        sql = text("""
        INSERT INTO physical_registry.manufacturers (id, name, country, website)
        VALUES (gen_random_uuid(), :name, :country, :website)
        ON CONFLICT (name) DO UPDATE SET
          country = COALESCE(EXCLUDED.country, manufacturers.country),
          website = COALESCE(EXCLUDED.website, manufacturers.website),
          updated_at = now()
        RETURNING id, name, country, website, created_at, updated_at
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=None)
            try:
                r = await c.execute(sql, {"name": name, "country": country, "website": website})
                return r.mappings().one()
            except IntegrityError as e:
                raise ConflictError(str(e)) from e

    async def upsert_device_model(
        self,
        manufacturer_id: str,
        name: str,
        hardware_rev: Optional[str] = None,
        interfaces: Optional[Mapping[str, Any]] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        sql = text("""
        INSERT INTO physical_registry.device_models (id, manufacturer_id, name, hardware_rev, description, interfaces)
        VALUES (gen_random_uuid(), :mfr_id, :name, :hw, :descr, CAST(:ifaces AS jsonb))
        ON CONFLICT (manufacturer_id, name, COALESCE(hardware_rev, ''))
        DO UPDATE SET
          description = COALESCE(EXCLUDED.description, device_models.description),
          interfaces  = COALESCE(EXCLUDED.interfaces, device_models.interfaces),
          updated_at  = now()
        RETURNING id, manufacturer_id, name, hardware_rev, description, interfaces, created_at, updated_at
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=None)
            try:
                r = await c.execute(sql, {
                    "mfr_id": manufacturer_id,
                    "name": name,
                    "hw": hardware_rev,
                    "descr": description,
                    "ifaces": interfaces or {},
                })
                return r.mappings().one()
            except IntegrityError as e:
                raise ConflictError(str(e)) from e

    # ---- DEVICES ---------------------------------------------------------------

    async def upsert_device(
        self,
        tenant_id: str,
        *,
        manufacturer_id: str,
        model_id: str,
        device_uid: str,
        serial_number: Optional[str] = None,
        status: str = "provisioned",
        labels: Optional[Mapping[str, Any]] = None,
        location: Optional[Mapping[str, Any]] = None,
        manufactured_at: Optional[datetime] = None,
        commissioned_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Идемпотентный upsert по (tenant_id, device_uid). Лейблы мержатся (||).
        Учитывает уникальность serial_number в пределах tenant.
        """
        sql = text("""
        INSERT INTO devices (id, tenant_id, manufacturer_id, model_id, device_uid, serial_number,
                             status, labels, location, manufactured_at, commissioned_at)
        VALUES (gen_random_uuid(), :tid, :mfr, :model, :uid, :serial,
                :status, CAST(:labels AS jsonb), CAST(:loc AS jsonb), :mfg_at, :comm_at)
        ON CONFLICT (tenant_id, device_uid) DO UPDATE SET
          manufacturer_id = EXCLUDED.manufacturer_id,
          model_id        = EXCLUDED.model_id,
          serial_number   = EXCLUDED.serial_number,
          labels          = COALESCE(devices.labels, '{}'::jsonb) || COALESCE(EXCLUDED.labels, '{}'::jsonb),
          location        = COALESCE(EXCLUDED.location, devices.location),
          commissioned_at = COALESCE(devices.commissioned_at, EXCLUDED.commissioned_at),
          status          = EXCLUDED.status,
          updated_at      = now()
        RETURNING id, tenant_id, manufacturer_id, model_id, device_uid, serial_number, status,
                  labels, location, manufactured_at, commissioned_at, last_seen_at, created_at, updated_at
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            try:
                r = await c.execute(sql, {
                    "tid": tenant_id,
                    "mfr": manufacturer_id,
                    "model": model_id,
                    "uid": device_uid,
                    "serial": serial_number,
                    "status": status,
                    "labels": labels or {},
                    "loc": location or {},
                    "mfg_at": manufactured_at,
                    "comm_at": commissioned_at,
                })
                return r.mappings().one()
            except IntegrityError as e:
                # Может быть конфликт по serial_number (unique (tenant_id, serial_number))
                raise ConflictError("device upsert conflict: unique constraint") from e
            except OperationalError as e:
                raise RepositoryError(str(e)) from e

    async def get_device_by_uid(self, tenant_id: str, device_uid: str) -> Dict[str, Any]:
        sql = text("""
        SELECT d.* FROM devices d
        WHERE d.tenant_id = :tid AND d.device_uid = :uid
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            row = (await c.execute(sql, {"tid": tenant_id, "uid": device_uid})).mappings().one_or_none()
            if not row:
                raise NotFoundError("device not found")
            return dict(row)

    async def list_devices(
        self,
        tenant_id: str,
        *,
        status: Optional[str] = None,
        manufacturer_id: Optional[str] = None,
        model_id: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        # Простая пагинация offset/limit (при необходимости заменить на keyset)
        where = ["d.tenant_id = :tid"]
        params: Dict[str, Any] = {"tid": tenant_id, "limit": limit, "offset": offset}
        if status:
            where.append("d.status = :status")
            params["status"] = status
        if manufacturer_id:
            where.append("d.manufacturer_id = :mfr")
            params["mfr"] = manufacturer_id
        if model_id:
            where.append("d.model_id = :model")
            params["model"] = model_id
        if q:
            where.append("(d.device_uid ILIKE :q OR d.serial_number ILIKE :q)")
            params["q"] = f"%{q}%"

        sql = text(f"""
        SELECT d.id, d.device_uid, d.serial_number, d.status, d.labels, d.location,
               d.manufacturer_id, d.model_id, d.last_seen_at, d.created_at, d.updated_at
        FROM devices d
        WHERE {' AND '.join(where)}
        ORDER BY d.created_at DESC, d.id DESC
        LIMIT :limit OFFSET :offset
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            rows = (await c.execute(sql, params)).mappings().all()
            return [dict(r) for r in rows]

    async def touch_last_seen(self, tenant_id: str, device_id: str, ts: Optional[datetime] = None) -> None:
        sql = text("UPDATE devices SET last_seen_at = COALESCE(:ts, now()), updated_at = now() WHERE id = :id")
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id, statement_timeout_ms=1500)
            r = await c.execute(sql, {"ts": ts, "id": device_id})
            if r.rowcount == 0:
                raise NotFoundError("device not found")

    # ---- SENSORS ---------------------------------------------------------------

    async def upsert_sensor(
        self,
        tenant_id: str,
        *,
        device_id: str,
        kind: str,
        channel: str,
        unit_ucum: Optional[str] = None,
        labels: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        sql = text("""
        INSERT INTO sensors (id, device_id, kind, channel, unit_ucum, labels)
        VALUES (gen_random_uuid(), :dev, :kind, :ch, :unit, CAST(:labels AS jsonb))
        ON CONFLICT (device_id, kind, channel) DO UPDATE SET
          unit_ucum = EXCLUDED.unit_ucum,
          labels    = COALESCE(EXCLUDED.labels, sensors.labels),
          updated_at = now()
        RETURNING id, device_id, kind, channel, unit_ucum, labels, created_at, updated_at
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            try:
                r = await c.execute(sql, {"dev": device_id, "kind": kind, "ch": channel, "unit": unit_ucum, "labels": labels or {}})
                return r.mappings().one()
            except IntegrityError as e:
                # FK на devices может сработать
                raise ConflictError("sensor upsert conflict (device or unique)") from e

    async def list_sensors(self, tenant_id: str, device_id: str) -> List[Dict[str, Any]]:
        sql = text("""
        SELECT s.id, s.device_id, s.kind, s.channel, s.unit_ucum, s.labels, s.created_at, s.updated_at
        FROM sensors s
        WHERE s.device_id = :dev
        ORDER BY s.kind, s.channel
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            rows = (await c.execute(sql, {"dev": device_id})).mappings().all()
            return [dict(r) for r in rows]

    # ---- KV LABELS -------------------------------------------------------------

    async def set_device_label(self, tenant_id: str, device_id: str, key: str, value: str) -> Dict[str, Any]:
        sql = text("""
        INSERT INTO device_kv_labels (id, device_id, key, value)
        VALUES (gen_random_uuid(), :dev, :k, :v)
        ON CONFLICT (device_id, key) DO UPDATE SET
          value = EXCLUDED.value,
          updated_at = now()
        RETURNING id, device_id, key, value, created_at, updated_at
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            try:
                r = await c.execute(sql, {"dev": device_id, "k": key, "v": value})
                return r.mappings().one()
            except IntegrityError as e:
                raise ConflictError("label upsert conflict") from e

    async def list_device_labels(self, tenant_id: str, device_id: str) -> List[Dict[str, Any]]:
        sql = text("SELECT id, key, value, created_at, updated_at FROM device_kv_labels WHERE device_id = :dev ORDER BY key")
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            rows = (await c.execute(sql, {"dev": device_id})).mappings().all()
            return [dict(r) for r in rows]

    # ---- FIRMWARE CATALOG ------------------------------------------------------

    async def add_firmware(
        self,
        *,
        model_id: Optional[str],
        version: str,
        image_uri: str,
        sha256: str,
        signed: bool = True,
        release_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Регистрация прошивки в каталоге (semver проверяется CHECK-ом).
        """
        sql = text("""
        INSERT INTO physical_registry.firmwares (id, model_id, version, image_uri, sha256, signed, release_notes)
        VALUES (gen_random_uuid(), :model, :ver, :uri, :sha, :signed, :notes)
        RETURNING id, model_id, version, image_uri, sha256, signed, release_notes, created_at, updated_at
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=None)
            try:
                r = await c.execute(sql, {"model": model_id, "ver": version, "uri": image_uri, "sha": sha256, "signed": signed, "notes": release_notes})
                return r.mappings().one()
            except IntegrityError as e:
                raise ConflictError("firmware already exists for model/version") from e

    async def set_device_current_firmware(self, tenant_id: str, device_id: str, firmware_id: str) -> None:
        """
        Назначает текущую прошивку устройству: все предыдущие помечаются как неактуальные.
        """
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            try:
                # Скинуть флаг текущей
                await c.execute(text("UPDATE device_firmwares SET is_current = false WHERE device_id = :dev"), {"dev": device_id})
                # Связать указанную прошивку с устройством (upsert)
                await c.execute(text("""
                INSERT INTO device_firmwares (id, device_id, firmware_id, is_current, installed_at)
                VALUES (gen_random_uuid(), :dev, :fw, true, now())
                ON CONFLICT (device_id, firmware_id) DO UPDATE SET is_current = true, installed_at = COALESCE(device_firmwares.installed_at, now()), updated_at = now()
                """), {"dev": device_id, "fw": firmware_id})
            except IntegrityError as e:
                raise ConflictError("invalid device/firmware relation") from e

    # ---- DEVICE CREDENTIALS ----------------------------------------------------

    async def rotate_device_credential(
        self,
        tenant_id: str,
        *,
        device_id: str,
        cred_type: str,                         # 'psk' | 'x509' | 'oauth2' | 'jwt' | 'none'
        public_key_pem: Optional[str] = None,
        secret_encrypted: Optional[bytes] = None,
        not_after: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Завершает (not_after=now()) прежние креды данного типа и создаёт свежие для устройства.
        """
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            try:
                await c.execute(text("""
                    UPDATE device_credentials
                    SET not_after = COALESCE(not_after, now()), updated_at = now()
                    WHERE device_id = :dev AND type = :t AND (not_after IS NULL OR not_after > now())
                """), {"dev": device_id, "t": cred_type})
                row = (await c.execute(text("""
                    INSERT INTO device_credentials (id, device_id, type, public_key_pem, secret_encrypted, not_before, not_after)
                    VALUES (gen_random_uuid(), :dev, :t, :pub, :sec, now(), :na)
                    RETURNING id, device_id, type, public_key_pem, not_before, not_after, created_at, updated_at
                """), {"dev": device_id, "t": cred_type, "pub": public_key_pem, "sec": secret_encrypted, "na": not_after})).mappings().one()
                return dict(row)
            except IntegrityError as e:
                raise ConflictError("credential rotation conflict") from e

    # ---- SEARCH VIEW -----------------------------------------------------------

    async def search_devices_full(
        self,
        tenant_id: str,
        *,
        q: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Поиск по представлению v_device_full (см. миграцию). Находит по UID, серийнику, производителю, модели.
        """
        where = ["tenant_id = :tid"]
        params: Dict[str, Any] = {"tid": tenant_id, "limit": limit, "offset": offset}
        if q:
            where.append("(device_uid ILIKE :q OR serial_number ILIKE :q OR manufacturer ILIKE :q OR model ILIKE :q)")
            params["q"] = f"%{q}%"

        sql = text(f"""
        SELECT id, device_uid, serial_number, status, manufacturer, model, model_hw_rev,
               labels, location, current_fw_version, last_seen_at, created_at, updated_at
        FROM physical_registry.v_device_full
        WHERE {' AND '.join(where)}
        ORDER BY created_at DESC, id DESC
        LIMIT :limit OFFSET :offset
        """)
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            rows = (await c.execute(sql, params)).mappings().all()
            return [dict(r) for r in rows]

    # ---- Утилиты ---------------------------------------------------------------

    async def ensure_tenant_context(self, tenant_id: str) -> None:
        """
        Быстрая проверка, что политики RLS/контекст арендатора работают (SELECT 1 под policy).
        """
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id, statement_timeout_ms=1000)
            await c.execute(text("SELECT 1"))

    # Пример транзакции с несколькими действиями
    async def register_device_with_sensors(
        self,
        tenant_id: str,
        *,
        manufacturer_id: str,
        model_id: str,
        device_uid: str,
        sensors: Sequence[Tuple[str, str, Optional[str]]],  # [(kind, channel, unit_ucum)]
        serial_number: Optional[str] = None,
        labels: Optional[Mapping[str, Any]] = None,
        location: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Транзакционное создание/обновление устройства и набора сенсоров.
        """
        async with self._conn() as c:
            await self._prepare_session(c, tenant_id=tenant_id)
            try:
                dev = (await c.execute(text("""
                    INSERT INTO devices (id, tenant_id, manufacturer_id, model_id, device_uid, serial_number, status, labels, location)
                    VALUES (gen_random_uuid(), :tid, :mfr, :model, :uid, :serial, 'provisioned', CAST(:labels AS jsonb), CAST(:loc AS jsonb))
                    ON CONFLICT (tenant_id, device_uid) DO UPDATE SET
                      serial_number = EXCLUDED.serial_number,
                      manufacturer_id = EXCLUDED.manufacturer_id,
                      model_id = EXCLUDED.model_id,
                      labels = COALESCE(devices.labels, '{}'::jsonb) || COALESCE(EXCLUDED.labels, '{}'::jsonb),
                      location = COALESCE(EXCLUDED.location, devices.location),
                      updated_at = now()
                    RETURNING id, device_uid
                """), {"tid": tenant_id, "mfr": manufacturer_id, "model": model_id, "uid": device_uid,
                       "serial": serial_number, "labels": labels or {}, "loc": location or {}})).mappings().one()
                device_id = dev["id"]
                for kind, channel, unit in sensors:
                    await c.execute(text("""
                        INSERT INTO sensors (id, device_id, kind, channel, unit_ucum)
                        VALUES (gen_random_uuid(), :dev, :kind, :ch, :unit)
                        ON CONFLICT (device_id, kind, channel) DO UPDATE SET unit_ucum = EXCLUDED.unit_ucum, updated_at = now()
                    """), {"dev": device_id, "kind": kind, "ch": channel, "unit": unit})
                return {"device_id": device_id, "device_uid": dev["device_uid"], "sensors": len(sensors)}
            except IntegrityError as e:
                raise ConflictError("register device transaction failed") from e
            except OperationalError as e:
                raise RepositoryError(str(e)) from e
