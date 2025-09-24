# datafabric-core/datafabric/storage/catalog/hive_metastore.py
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, validator

# ===================== Протоколы метрик/трейсинга =====================

class Metrics:
    async def inc(self, name: str, value: int = 1, **labels: str) -> None:
        return
    async def observe(self, name: str, value: float, **labels: str) -> None:
        return

class Tracer:
    def start_span(self, name: str, **attrs: Any) -> "Span":
        return Span()

class Span:
    def set_attribute(self, key: str, value: Any) -> None:
        return
    def record_exception(self, exc: BaseException) -> None:
        return
    def end(self) -> None:
        return

# =============================== Конфиг ===============================

class RetryConfig(BaseModel):
    max_attempts: int = Field(6, ge=1, le=15)
    base_delay_ms: int = Field(100, ge=1)
    max_delay_ms: int = Field(20_000, ge=100)
    jitter_ms: int = Field(300, ge=0)
    exponential_factor: float = Field(2.0, ge=1.0)

class ThriftAuth(BaseModel):
    sasl_enabled: bool = Field(False, description="Включить SASL (PLAIN или KERBEROS)")
    mechanism: str = Field("PLAIN", description="PLAIN|KERBEROS")
    username: Optional[str] = None
    password: Optional[str] = None
    kerberos_service: str = Field("hive", description="Имя сервиса Kerberos (hive/hiveserver2)")

class ThriftTLS(BaseModel):
    enabled: bool = Field(False)
    ca_path: Optional[str] = None
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    verify: bool = Field(True)

class HiveMetastoreConfig(BaseModel):
    backend: str = Field("thrift", description="thrift|glue")
    # Общие
    retries: RetryConfig = RetryConfig()
    metrics_prefix: str = Field("datafabric_hms")
    max_concurrency: int = Field(16, ge=1, le=128)

    # Thrift HMS
    host: str = Field("localhost")
    port: int = Field(9083, ge=1, le=65535)
    transport_timeout_s: int = Field(30, ge=1)
    thrift_auth: ThriftAuth = ThriftAuth()
    thrift_tls: ThriftTLS = ThriftTLS()

    # SQL fallback (MSCK REPAIR и DDL через Hive)
    sql_fallback_dsn: Optional[str] = Field(None, description="Опционально: pyhive.hive DSN для SQL‑операций")

    # Glue
    glue_region: Optional[str] = None
    glue_catalog_id: Optional[str] = None
    glue_profile: Optional[str] = None
    glue_endpoint_url: Optional[str] = None

    @validator("backend")
    def _val_backend(cls, v: str) -> str:
        v = v.lower()
        if v not in ("thrift", "glue"):
            raise ValueError("backend must be thrift|glue")
        return v

# ============================ Исключения ==============================

class MetastoreError(Exception): ...
class NotFound(MetastoreError): ...
class Conflict(MetastoreError): ...
class Unsupported(MetastoreError): ...

# ============================ Утилиты ==============================

def _compute_backoff(attempt: int, cfg: RetryConfig) -> float:
    base = cfg.base_delay_ms / 1000.0
    delay = min(base * (cfg.exponential_factor ** (attempt - 1)), cfg.max_delay_ms / 1000.0)
    jitter = (cfg.jitter_ms / 1000.0) * (os.urandom(1)[0] / 255.0) if cfg.jitter_ms > 0 else 0.0
    return delay + jitter

def _partition_kv_to_hive_path(spec: Mapping[str, Any]) -> str:
    def sanitize(v: Any) -> str:
        if v is None:
            return "__NULL__"
        s = str(v)
        return s.replace("/", "_").replace("=", "_")
    parts = [f"{k}={sanitize(v)}" for k, v in spec.items()]
    return "/".join(parts)

def _normalize_columns(columns: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """
    columns: [{name, type, comment?}] ; type в Hive синтаксисе (string, int, bigint, decimal(10,2), struct<...> и т.п.)
    """
    out: List[Dict[str, Any]] = []
    for c in columns:
        nm = str(c["name"]).strip()
        tp = str(c["type"]).strip()
        cm = str(c.get("comment", "")).strip() or None
        if not nm or not tp:
            raise MetastoreError("column must have name and type")
        out.append({"name": nm, "type": tp, "comment": cm})
    return out

# ============================ Модель таблицы ==============================

@dataclass
class TableInfo:
    database: str
    table: str
    location: Optional[str]
    columns: List[Dict[str, Any]]
    partition_columns: List[Dict[str, Any]]
    input_format: Optional[str]
    output_format: Optional[str]
    serde_lib: Optional[str]
    serde_params: Dict[str, str]
    table_params: Dict[str, str]
    owner: Optional[str] = None

# ============================ Бэкенды ==============================

class _Backend:
    async def start(self) -> None: ...
    async def close(self) -> None: ...
    async def ensure_database(self, name: str, *, location: Optional[str], props: Optional[Dict[str, str]]) -> None: ...
    async def get_table(self, db: str, table: str) -> TableInfo: ...
    async def create_or_alter_table(
        self,
        db: str,
        table: str,
        *,
        columns: Sequence[Mapping[str, Any]],
        partition_columns: Sequence[Mapping[str, Any]],
        location: Optional[str],
        serde_lib: Optional[str],
        input_format: Optional[str],
        output_format: Optional[str],
        serde_params: Optional[Dict[str, str]],
        table_params: Optional[Dict[str, str]],
    ) -> None: ...
    async def upsert_partitions(self, db: str, table: str, parts: Sequence[Mapping[str, Any]], *, locations: Optional[Sequence[str]] = None) -> None: ...
    async def drop_partitions(self, db: str, table: str, parts: Sequence[Mapping[str, Any]], *, if_exists: bool = True) -> None: ...
    async def get_partitions(self, db: str, table: str, *, expression: Optional[str], max_parts: Optional[int]) -> List[Dict[str, Any]]: ...
    async def set_table_properties(self, db: str, table: str, props: Dict[str, str], *, unset: Optional[Sequence[str]]) -> None: ...
    async def get_table_location(self, db: str, table: str) -> Optional[str]: ...
    async def repair_table(self, db: str, table: str) -> None: ...

# -------- Thrift backend (опциональные зависимости) --------

class _ThriftBackend(_Backend):
    def __init__(self, cfg: HiveMetastoreConfig, metrics: Metrics, tracer: Tracer) -> None:
        self.cfg = cfg
        self.metrics = metrics
        self.tracer = tracer
        self._client = None  # ThriftHiveMetastore.Client
        self._transport = None

    async def start(self) -> None:
        span = self.tracer.start_span("hms.thrift.start", host=self.cfg.host, port=self.cfg.port)
        try:
            # Ленивая загрузка thrift‑зависимостей
            from thrift.transport import TSocket, TSSLSocket, TTransport  # type: ignore
            from thrift.protocol import TBinaryProtocol  # type: ignore
            # hmsclient предоставляет обертки ThriftHiveMetastore
            try:
                from hmsclient import hmsclient  # type: ignore
                client_factory = hmsclient.HMSClient
            except Exception:
                client_factory = None

            # Транспорт
            if self.cfg.thrift_tls.enabled:
                sock = TSSLSocket.TSSLSocket(
                    host=self.cfg.host,
                    port=self.cfg.port,
                    ca_certs=self.cfg.thrift_tls.ca_path,
                    certfile=self.cfg.thrift_tls.cert_path,
                    keyfile=self.cfg.thrift_tls.key_path,
                    validate=self.cfg.thrift_tls.verify,
                )
            else:
                sock = TSocket.TSocket(self.cfg.host, self.cfg.port)
            sock.setTimeout(self.cfg.transport_timeout_s * 1000)
            trans: Any = TTransport.TBufferedTransport(sock)

            # SASL (если доступна библиотека sasl)
            if self.cfg.thrift_auth.sasl_enabled:
                try:
                    from thrift_sasl import TSaslClientTransport  # type: ignore
                    mech = self.cfg.thrift_auth.mechanism.upper()
                    if mech == "PLAIN":
                        trans = TSaslClientTransport(
                            trans,
                            host=self.cfg.host,
                            service="hive",
                            mechanism="PLAIN",
                            username=self.cfg.thrift_auth.username or "anonymous",
                            password=self.cfg.thrift_auth.password or "",
                        )
                    elif mech == "KERBEROS":
                        trans = TSaslClientTransport(
                            trans,
                            host=self.cfg.host,
                            service=self.cfg.thrift_auth.kerberos_service or "hive",
                            mechanism="GSSAPI",
                        )
                    else:
                        raise Unsupported(f"Unsupported SASL mechanism: {mech}")
                except Exception as e:
                    raise Unsupported("SASL requested but thrift_sasl is not available") from e

            proto = TBinaryProtocol.TBinaryProtocol(trans)
            if client_factory:
                self._client = client_factory(host=self.cfg.host, port=self.cfg.port).__enter__()  # type: ignore
                # hmsclient сам открывает соединение; используем его. Транспорт backup для закрытия.
                self._transport = None
            else:
                # Пробуем использовать сгенерированный thrift‑клиент Metastore (если установлен)
                try:
                    from hive_metastore import ThriftHiveMetastore  # type: ignore
                except Exception as e:
                    raise Unsupported("No hmsclient or ThriftHiveMetastore available") from e
                self._transport = trans
                self._transport.open()
                self._client = ThriftHiveMetastore.Client(proto)  # type: ignore
        except Exception as e:
            span.record_exception(e)
            raise MetastoreError(f"Failed to start Thrift HMS: {e}") from e
        finally:
            span.end()

    async def close(self) -> None:
        try:
            if self._client and hasattr(self._client, "__exit__"):
                with _suppress():
                    self._client.__exit__(None, None, None)
            if self._transport:
                with _suppress():
                    self._transport.close()
        finally:
            self._client = None
            self._transport = None

    async def ensure_database(self, name: str, *, location: Optional[str], props: Optional[Dict[str, str]]) -> None:
        async def _op():
            try:
                await self._wrap("get_database", name)
                return
            except NotFound:
                pass
            db = {
                "name": name,
                "description": "",
                "locationUri": location,
                "parameters": props or {},
                "ownerName": None,
                "ownerType": 0,
            }
            await self._wrap("create_database", db)

        await self._retry(_op, "ensure_database")

    async def get_table(self, db: str, table: str) -> TableInfo:
        def _conv(tbl: Any) -> TableInfo:
            sd = tbl.sd
            serde = sd.serdeInfo
            cols = [{"name": f.name, "type": f.type, "comment": getattr(f, "comment", None)} for f in sd.cols]
            parts = [{"name": f.name, "type": f.type, "comment": getattr(f, "comment", None)} for f in tbl.partitionKeys]
            return TableInfo(
                database=db,
                table=table,
                location=sd.location,
                columns=cols,
                partition_columns=parts,
                input_format=sd.inputFormat,
                output_format=sd.outputFormat,
                serde_lib=serde.serializationLib if serde else None,
                serde_params=(serde.parameters or {}) if serde else {},
                table_params=(tbl.parameters or {}),
                owner=tbl.owner,
            )

        async def _op():
            tbl = await self._wrap("get_table", db, table)
            return _conv(tbl)

        return await self._retry(_op, "get_table")

    async def create_or_alter_table(
        self,
        db: str,
        table: str,
        *,
        columns: Sequence[Mapping[str, Any]],
        partition_columns: Sequence[Mapping[str, Any]],
        location: Optional[str],
        serde_lib: Optional[str],
        input_format: Optional[str],
        output_format: Optional[str],
        serde_params: Optional[Dict[str, str]],
        table_params: Optional[Dict[str, str]],
    ) -> None:
        cols = _normalize_columns(columns)
        parts = _normalize_columns(partition_columns)

        async def _op():
            try:
                existing = await self._wrap("get_table", db, table)
                # alter: обновляем schema/location/serde/params
                existing.sd.location = location or existing.sd.location
                if serde_lib or serde_params:
                    existing.sd.serdeInfo.serializationLib = serde_lib or existing.sd.serdeInfo.serializationLib
                    if serde_params:
                        existing.sd.serdeInfo.parameters.update(serde_params)
                if input_format:
                    existing.sd.inputFormat = input_format
                if output_format:
                    existing.sd.outputFormat = output_format
                # колонки
                if cols:
                    existing.sd.cols = [self._mk_field(c) for c in cols]
                if parts:
                    existing.partitionKeys = [self._mk_field(c) for c in parts]
                if table_params:
                    existing.parameters.update(table_params)
                await self._wrap("alter_table", db, table, existing)
                return
            except NotFound:
                pass

            tbl = self._mk_table(db, table, cols, parts, location, serde_lib, input_format, output_format, serde_params, table_params)
            await self._wrap("create_table", tbl)

        await self._retry(_op, "create_or_alter_table")

    async def upsert_partitions(self, db: str, table: str, parts: Sequence[Mapping[str, Any]], *, locations: Optional[Sequence[str]] = None) -> None:
        parts = list(parts)
        locs = list(locations or [])
        if locs and len(locs) != len(parts):
            raise MetastoreError("locations length must equal partitions length")

        async def _op():
            # Пытаемся batch‑добавить; если существует — игнорируем конфликт
            part_objs = []
            for i, spec in enumerate(parts):
                kv = list(spec.items())
                values = [str(v if v is not None else "__NULL__") for _, v in kv]
                loc = locs[i] if i < len(locs) else None
                part_objs.append(self._mk_partition(db, table, values, location=loc))
            try:
                await self._wrap("add_partitions", part_objs)
            except Conflict:
                # часть уже существует — делаем alter для локаций
                for i, spec in enumerate(parts):
                    kv = list(spec.items())
                    values = [str(v if v is not None else "__NULL__") for _, v in kv]
                    try:
                        p = await self._wrap("get_partition", db, table, values)
                        if locs:
                            p.sd.location = locs[i]
                            await self._wrap("alter_partition", db, table, p)
                    except NotFound:
                        # гонка — создать отдельно
                        await self._wrap("add_partition", self._mk_partition(db, table, values, location=locs[i] if i < len(locs) else None))

        await self._retry(_op, "upsert_partitions")

    async def drop_partitions(self, db: str, table: str, parts: Sequence[Mapping[str, Any]], *, if_exists: bool = True) -> None:
        async def _op():
            for spec in parts:
                kv = list(spec.items())
                values = [str(v if v is not None else "__NULL__") for _, v in kv]
                try:
                    await self._wrap("drop_partition", db, table, values, deleteData=False)
                except NotFound:
                    if not if_exists:
                        raise

        await self._retry(_op, "drop_partitions")

    async def get_partitions(self, db: str, table: str, *, expression: Optional[str], max_parts: Optional[int]) -> List[Dict[str, Any]]:
        async def _op():
            if expression:
                plist = await self._wrap("list_partitions_by_expr", db, table, expression, max_parts or 1000)
            else:
                plist = await self._wrap("get_partitions", db, table, max_parts or 1000)
            out: List[Dict[str, Any]] = []
            for p in plist:
                spec = dict(zip([k.name for k in p.values], [v for v in p.values])) if hasattr(p, "values") else {}
                out.append({"values": spec, "location": getattr(p.sd, "location", None)})
            return out

        return await self._retry(_op, "get_partitions")

    async def set_table_properties(self, db: str, table: str, props: Dict[str, str], *, unset: Optional[Sequence[str]]) -> None:
        async def _op():
            t = await self._wrap("get_table", db, table)
            t.parameters = t.parameters or {}
            t.parameters.update(props or {})
            if unset:
                for k in unset:
                    t.parameters.pop(k, None)
            await self._wrap("alter_table", db, table, t)

        await self._retry(_op, "set_table_properties")

    async def get_table_location(self, db: str, table: str) -> Optional[str]:
        t = await self.get_table(db, table)
        return t.location

    async def repair_table(self, db: str, table: str) -> None:
        # У HMS нет MSCK; можно через SQL fallback
        if not self.cfg.sql_fallback_dsn:
            raise Unsupported("repair_table requires sql_fallback_dsn (HiveServer2) for MSCK REPAIR TABLE")
        await _sql_msck_repair(self.cfg.sql_fallback_dsn, db, table, self.metrics, self.cfg.metrics_prefix)

    # ---------- helpers ----------

    def _mk_field(self, c: Mapping[str, Any]):
        # Создаёт объект FieldSchema для thrift клиента
        from hive_metastore import hive_metastore  # type: ignore
        return hive_metastore.FieldSchema(name=c["name"], type=c["type"], comment=c.get("comment"))

    def _mk_table(
        self,
        db: str,
        table: str,
        cols: Sequence[Mapping[str, Any]],
        parts: Sequence[Mapping[str, Any]],
        location: Optional[str],
        serde_lib: Optional[str],
        input_format: Optional[str],
        output_format: Optional[str],
        serde_params: Optional[Dict[str, str]],
        table_params: Optional[Dict[str, str]],
    ):
        from hive_metastore import hive_metastore  # type: ignore
        sd = hive_metastore.StorageDescriptor(
            cols=[self._mk_field(c) for c in cols],
            location=location,
            inputFormat=input_format,
            outputFormat=output_format,
            compressed=False,
            numBuckets=0,
            serdeInfo=hive_metastore.SerDeInfo(
                name=f"{table}_serde",
                serializationLib=serde_lib,
                parameters=serde_params or {},
            ),
            bucketCols=[],
            sortCols=[],
            parameters={},
            skewedInfo=None,
            storedAsSubDirectories=False,
        )
        return hive_metastore.Table(
            dbName=db,
            tableName=table,
            owner="owner",
            createTime=int(time.time()),
            lastAccessTime=int(time.time()),
            retention=0,
            sd=sd,
            partitionKeys=[self._mk_field(c) for c in parts],
            parameters=table_params or {},
            viewOriginalText=None,
            viewExpandedText=None,
            tableType="EXTERNAL_TABLE",
        )

    def _mk_partition(self, db: str, table: str, values: Sequence[str], *, location: Optional[str]):
        from hive_metastore import hive_metastore  # type: ignore
        sd = hive_metastore.StorageDescriptor(
            cols=[],  # наследуются от таблицы
            location=location,
            inputFormat=None,
            outputFormat=None,
            compressed=False,
            numBuckets=0,
            serdeInfo=None,
            bucketCols=[],
            sortCols=[],
            parameters={},
            skewedInfo=None,
            storedAsSubDirectories=False,
        )
        return hive_metastore.Partition(values=list(values), dbName=db, tableName=table, createTime=int(time.time()), sd=sd, parameters={})

    async def _wrap(self, fn_name: str, *args, **kwargs):
        await self._ensure()
        fn = getattr(self._client, fn_name)
        # Thrift клиент синхронный — выполняем в thread pool
        def _call():
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                text = str(e)
                if "NoSuchObjectException" in text or "NoSuchObject" in text:
                    raise NotFound(text)
                if "AlreadyExistsException" in text or "AlreadyExists" in text:
                    raise Conflict(text)
                raise
        return await asyncio.to_thread(_call)

    async def _retry(self, op, name: str):
        attempt = 1
        span = self.tracer.start_span(f"hms.{name}")
        t0 = time.perf_counter()
        try:
            while True:
                try:
                    res = await op()
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_{name}_total")
                    return res
                except (Conflict, NotFound) as e:
                    # Эти ошибки намеренные — не ретраим
                    span.record_exception(e)
                    raise
                except Exception as e:
                    if attempt >= self.cfg.retries.max_attempts:
                        span.record_exception(e)
                        raise
                    await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                    attempt += 1
        finally:
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_{name}_seconds", time.perf_counter() - t0)
            span.end()

    async def _ensure(self):
        if self._client is None:
            await self.start()

# -------- Glue backend (опциональные зависимости) --------

class _GlueBackend(_Backend):
    def __init__(self, cfg: HiveMetastoreConfig, metrics: Metrics, tracer: Tracer) -> None:
        self.cfg = cfg
        self.metrics = metrics
        self.tracer = tracer
        self._client = None

    async def start(self) -> None:
        span = self.tracer.start_span("hms.glue.start", region=self.cfg.glue_region or "")
        try:
            import boto3  # type: ignore
            session = boto3.Session(profile_name=self.cfg.glue_profile, region_name=self.cfg.glue_region)
            self._client = session.client("glue", endpoint_url=self.cfg.glue_endpoint_url)
        except Exception as e:
            span.record_exception(e)
            raise MetastoreError(f"Failed to start Glue client: {e}") from e
        finally:
            span.end()

    async def close(self) -> None:
        self._client = None

    async def ensure_database(self, name: str, *, location: Optional[str], props: Optional[Dict[str, str]]) -> None:
        async def _op():
            try:
                await self._call("get_database", Name=name)
                return
            except NotFound:
                pass
            params = {"Name": name, "Parameters": props or {}}
            if location:
                params["CreateTableDefaultPermissions"] = []
                params["LocationUri"] = location
            await self._call("create_database", DatabaseInput=params)
        await self._retry(_op, "ensure_database")

    async def get_table(self, db: str, table: str) -> TableInfo:
        resp = await self._retry(lambda: self._call("get_table", DatabaseName=db, Name=table), "get_table")
        t = resp["Table"]
        sd = t["StorageDescriptor"]
        cols = [{"name": c["Name"], "type": c["Type"], "comment": c.get("Comment")} for c in sd.get("Columns", [])]
        parts = [{"name": c["Name"], "type": c["Type"], "comment": c.get("Comment")} for c in t.get("PartitionKeys", [])]
        serde = sd.get("SerdeInfo") or {}
        return TableInfo(
            database=db,
            table=table,
            location=sd.get("Location"),
            columns=cols,
            partition_columns=parts,
            input_format=sd.get("InputFormat"),
            output_format=sd.get("OutputFormat"),
            serde_lib=serde.get("SerializationLibrary"),
            serde_params=serde.get("Parameters", {}) or {},
            table_params=t.get("Parameters", {}) or {},
            owner=t.get("Owner"),
        )

    async def create_or_alter_table(
        self,
        db: str,
        table: str,
        *,
        columns: Sequence[Mapping[str, Any]],
        partition_columns: Sequence[Mapping[str, Any]],
        location: Optional[str],
        serde_lib: Optional[str],
        input_format: Optional[str],
        output_format: Optional[str],
        serde_params: Optional[Dict[str, str]],
        table_params: Optional[Dict[str, str]],
    ) -> None:
        cols = _normalize_columns(columns)
        parts = _normalize_columns(partition_columns)

        async def _op():
            tbl_input = {
                "Name": table,
                "StorageDescriptor": {
                    "Columns": [{"Name": c["name"], "Type": c["type"], "Comment": c.get("comment")} for c in cols],
                    "Location": location,
                    "InputFormat": input_format,
                    "OutputFormat": output_format,
                    "SerdeInfo": {
                        "SerializationLibrary": serde_lib,
                        "Parameters": serde_params or {},
                    },
                    "BucketColumns": [],
                    "SortColumns": [],
                    "Parameters": {},
                },
                "PartitionKeys": [{"Name": c["name"], "Type": c["type"], "Comment": c.get("comment")} for c in parts],
                "Parameters": table_params or {},
                "TableType": "EXTERNAL_TABLE",
            }
            try:
                await self._call("create_table", DatabaseName=db, TableInput=tbl_input)
            except Conflict:
                await self._call("update_table", DatabaseName=db, TableInput=tbl_input)

        await self._retry(_op, "create_or_alter_table")

    async def upsert_partitions(self, db: str, table: str, parts: Sequence[Mapping[str, Any]], *, locations: Optional[Sequence[str]] = None) -> None:
        parts = list(parts)
        locs = list(locations or [])
        if locs and len(locs) != len(parts):
            raise MetastoreError("locations length must equal partitions length")

        async def _op():
            entries = []
            for i, spec in enumerate(parts):
                values = [str(v if v is not None else "__NULL__") for _, v in spec.items()]
                ent = {
                    "Values": values,
                    "StorageDescriptor": {"Location": locs[i]} if locs else {},
                }
                entries.append(ent)
            # batch: create or update
            try:
                await self._call("batch_create_partition", DatabaseName=db, TableName=table, PartitionInputList=entries)
            except Conflict:
                # update where exists
                for ent in entries:
                    await self._call("update_partition", DatabaseName=db, TableName=table, PartitionValueList=ent["Values"], PartitionInput={"Values": ent["Values"], "StorageDescriptor": ent.get("StorageDescriptor", {})})

        await self._retry(_op, "upsert_partitions")

    async def drop_partitions(self, db: str, table: str, parts: Sequence[Mapping[str, Any]], *, if_exists: bool = True) -> None:
        async def _op():
            for spec in parts:
                values = [str(v if v is not None else "__NULL__") for _, v in spec.items()]
                try:
                    await self._call("delete_partition", DatabaseName=db, TableName=table, PartitionValues=values)
                except NotFound:
                    if not if_exists:
                        raise
        await self._retry(_op, "drop_partitions")

    async def get_partitions(self, db: str, table: str, *, expression: Optional[str], max_parts: Optional[int]) -> List[Dict[str, Any]]:
        async def _op():
            token = None
            out: List[Dict[str, Any]] = []
            while True:
                kw = {"DatabaseName": db, "TableName": table}
                if token:
                    kw["NextToken"] = token
                if expression:
                    kw["Expression"] = expression
                resp = await self._call("get_partitions", **kw)
                for p in resp.get("Partitions", []):
                    spec = dict(zip([k["Name"] for k in p.get("StorageDescriptor", {}).get("Columns", [])], []))  # Glue не возвращает map значений напрямую
                    out.append({"values": p.get("Values", []), "location": p.get("StorageDescriptor", {}).get("Location")})
                    if max_parts and len(out) >= max_parts:
                        return out[:max_parts]
                token = resp.get("NextToken")
                if not token:
                    break
            return out
        return await self._retry(_op, "get_partitions")

    async def set_table_properties(self, db: str, table: str, props: Dict[str, str], *, unset: Optional[Sequence[str]]) -> None:
        async def _op():
            t = (await self._call("get_table", DatabaseName=db, Name=table))["Table"]
            params = t.get("Parameters", {}) or {}
            params.update(props or {})
            if unset:
                for k in unset:
                    params.pop(k, None)
            t_input = {
                "Name": t["Name"],
                "StorageDescriptor": t["StorageDescriptor"],
                "PartitionKeys": t.get("PartitionKeys", []),
                "Parameters": params,
                "TableType": t.get("TableType", "EXTERNAL_TABLE"),
            }
            await self._call("update_table", DatabaseName=db, TableInput=t_input)
        await self._retry(_op, "set_table_properties")

    async def get_table_location(self, db: str, table: str) -> Optional[str]:
        t = await self.get_table(db, table)
        return t.location

    async def repair_table(self, db: str, table: str) -> None:
        # Glue не поддерживает MSCK — используйте внешние инструменты (Athena MSCK/Trino/HiveServer2)
        raise Unsupported("repair_table is not supported by Glue backend")

    # -------- helpers --------

    async def _call(self, fn_name: str, **kwargs):
        await self._ensure()
        fn = getattr(self._client, fn_name)
        def _sync():
            try:
                return fn(**kwargs)
            except Exception as e:
                text = str(e)
                code = getattr(getattr(e, "response", {}).get("Error", {}), "get", lambda *_: None)("Code")
                if "EntityNotFoundException" in text or code == "EntityNotFoundException":
                    raise NotFound(text)
                if "AlreadyExistsException" in text or code == "AlreadyExistsException":
                    raise Conflict(text)
                raise
        return await asyncio.to_thread(_sync)

    async def _retry(self, op, name: str):
        attempt = 1
        span = self.tracer.start_span(f"hms.{name}")
        t0 = time.perf_counter()
        try:
            while True:
                try:
                    res = await op()
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_{name}_total")
                    return res
                except (Conflict, NotFound) as e:
                    span.record_exception(e)
                    raise
                except Exception as e:
                    if attempt >= self.cfg.retries.max_attempts:
                        span.record_exception(e)
                        raise
                    await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                    attempt += 1
        finally:
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_{name}_seconds", time.perf_counter() - t0)
            span.end()

    async def _ensure(self):
        if self._client is None:
            await self.start()

# ============================ SQL fallback (MSCK) ==============================

async def _sql_msck_repair(dsn: str, db: str, table: str, metrics: Metrics, prefix: str) -> None:
    """
    Выполняет MSCK REPAIR TABLE через pyhive.hive (если установлен), иначе Unsupported.
    """
    try:
        from pyhive import hive  # type: ignore
    except Exception as e:
        raise Unsupported("pyhive.hive is required for MSCK REPAIR TABLE") from e

    def _run():
        conn = hive.connect(dsn) if "://" in dsn else hive.Connection(host=dsn)
        try:
            cur = conn.cursor()
            cur.execute(f"MSCK REPAIR TABLE `{db}`.`{table}`")
        finally:
            conn.close()

    t0 = time.perf_counter()
    try:
        await asyncio.to_thread(_run)
    finally:
        await metrics.observe(f"{prefix}_repair_seconds", time.perf_counter() - t0)

# ============================ Фасадный клиент ==============================

class HiveMetastoreClient:
    """
    Унифицированный клиент каталога с бэкендами:
      - Thrift Hive Metastore (предпочтительно для on‑prem/Hive/Presto/Trino)
      - AWS Glue Data Catalog (облачный вариант)
    """

    def __init__(
        self,
        cfg: HiveMetastoreConfig,
        *,
        metrics: Optional[Metrics] = None,
        tracer: Optional[Tracer] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.cfg = cfg
        self.metrics = metrics or Metrics()
        self.tracer = tracer or Tracer()
        self.loop = loop or asyncio.get_event_loop()
        self._sem = asyncio.Semaphore(cfg.max_concurrency)
        self._backend: _Backend = _GlueBackend(cfg, self.metrics, self.tracer) if cfg.backend == "glue" else _ThriftBackend(cfg, self.metrics, self.tracer)
        self._started = False

    async def start(self) -> None:
        if not self._started:
            await self._backend.start()
            self._started = True

    async def close(self) -> None:
        if self._started:
            await self._backend.close()
            self._started = False

    # --------- Public API ---------

    async def ensure_database(self, name: str, *, location: Optional[str] = None, props: Optional[Dict[str, str]] = None) -> None:
        async with self._guard():
            await self._backend.ensure_database(name, location=location, props=props)

    async def get_table(self, db: str, table: str) -> TableInfo:
        async with self._guard():
            return await self._backend.get_table(db, table)

    async def create_or_alter_table(
        self,
        db: str,
        table: str,
        *,
        columns: Sequence[Mapping[str, Any]],
        partition_columns: Sequence[Mapping[str, Any]] = (),
        location: Optional[str] = None,
        serde_lib: Optional[str] = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
        input_format: Optional[str] = "org.apache.hadoop.mapred.TextInputFormat",
        output_format: Optional[str] = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
        serde_params: Optional[Dict[str, str]] = None,
        table_params: Optional[Dict[str, str]] = None,
    ) -> None:
        async with self._guard():
            await self._backend.create_or_alter_table(
                db, table,
                columns=columns,
                partition_columns=partition_columns,
                location=location,
                serde_lib=serde_lib,
                input_format=_
