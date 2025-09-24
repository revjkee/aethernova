# oblivionvault-core/oblivionvault/adapters/storage_snowflake.py
"""
Snowflake storage adapter for OblivionVault.

Design goals:
- Async-first API, thread offloading for the sync Snowflake driver.
- Idempotent writes with idempotency_key and versioning.
- Strict SQL with explicit quoting and parameter binding.
- Schema/table auto-provisioning (idempotent).
- Transactions around multi-step operations.
- Structured logging and optional tracing/metrics (soft dependencies).
- Clear, typed domain errors.

This module intentionally avoids assuming project-internal base classes.
Integrate by wiring SnowflakeStorageAdapter into your IOC container.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

try:
    from pydantic import BaseModel, Field, SecretStr, field_validator
except Exception:  # pragma: no cover
    # Fallback to keep file importable if pydantic is missing
    BaseModel = object  # type: ignore
    Field = lambda default=None, **kwargs: default  # type: ignore
    SecretStr = str  # type: ignore
    def field_validator(*args, **kwargs):  # type: ignore
        def wrap(fn): return fn
        return wrap

_LOG = logging.getLogger(__name__)
_LOG.addHandler(logging.NullHandler())


# ========= Exceptions =========

class StorageError(Exception):
    """Base error for storage adapter."""


class StorageConfigError(StorageError):
    """Configuration is invalid or incomplete."""


class StorageConnectionError(StorageError):
    """Connection/driver error."""


class StorageConflictError(StorageError):
    """Conflict on insert (duplicate/version) when overwrite=False."""


class StorageNotFoundError(StorageError):
    """Requested secret/version not found."""


# ========= Config =========

class SnowflakeAuthType:
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"  # PKCS8


class SnowflakeAdapterConfig(BaseModel):
    account: str = Field(..., description="Snowflake account, e.g. xy12345.eu-central-1")
    user: str = Field(..., description="Snowflake user")
    authenticator: Optional[str] = Field(None, description="External SSO if used (e.g. 'externalbrowser')")
    auth_type: str = Field(SnowflakeAuthType.PASSWORD, description="password | private_key")
    password: Optional[SecretStr] = Field(None, description="Password (if auth_type=password)")
    private_key_path: Optional[str] = Field(None, description="Path to PKCS8 private key (if auth_type=private_key)")
    private_key_passphrase: Optional[SecretStr] = Field(None, description="Passphrase for private key (optional)")

    role: Optional[str] = Field(None, description="Snowflake role")
    warehouse: Optional[str] = Field(None, description="Warehouse")
    database: str = Field(..., description="Database")
    schema: str = Field(..., description="Schema")
    table: str = Field("vault_secrets", description="Table name")

    login_timeout_s: int = Field(30, ge=1, le=300)
    network_timeout_s: int = Field(60, ge=1, le=600)

    session_parameters: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("auth_type")
    @classmethod
    def _auth_type_valid(cls, v: str) -> str:
        if v not in (SnowflakeAuthType.PASSWORD, SnowflakeAuthType.PRIVATE_KEY):
            raise StorageConfigError("auth_type must be 'password' or 'private_key'")
        return v

    @field_validator("password", mode="before")
    @classmethod
    def _password_env(cls, v):
        # Allow env var SNOWFLAKE_PASSWORD if password not set
        if v is None:
            env = os.getenv("SNOWFLAKE_PASSWORD")
            if env:
                return SecretStr(env)
        return v

    @field_validator("private_key_path", mode="before")
    @classmethod
    def _key_env(cls, v):
        # Allow env var SNOWFLAKE_PRIVATE_KEY_PATH
        return v or os.getenv("SNOWFLAKE_PRIVATE_KEY_PATH")


# ========= Utilities =========

def _quote_ident(ident: str) -> str:
    if ident is None:
        raise StorageConfigError("Identifier cannot be None")
    return '"' + ident.replace('"', '""') + '"'


def _qname(database: str, schema: str, table: str) -> str:
    return f"{_quote_ident(database)}.{_quote_ident(schema)}.{_quote_ident(table)}"


def _json_dumps_compact(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


async def _to_thread(func, /, *args, **kwargs):
    return await asyncio.to_thread(func, *args, **kwargs)


def _load_private_key(path: str, passphrase: Optional[str]) -> bytes:
    try:
        from cryptography.hazmat.primitives import serialization  # type: ignore
    except Exception as e:  # pragma: no cover
        raise StorageConfigError(
            "cryptography package required for private_key authentication"
        ) from e
    with open(path, "rb") as f:
        data = f.read()
    password_bytes = passphrase.encode("utf-8") if passphrase else None
    key = serialization.load_pem_private_key(data, password=password_bytes)
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ========= Adapter =========

@dataclass
class SecretRecord:
    namespace: str
    key: str
    version: int
    ciphertext: bytes
    metadata: Dict[str, Any]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    idempotency_key: Optional[str] = None


class SnowflakeStorageAdapter:
    """
    Async adapter to store encrypted secrets in Snowflake.

    Table definition (created automatically if missing):
        CREATE TABLE IF NOT EXISTS <db>.<schema>.<table> (
          namespace STRING NOT NULL,
          key STRING NOT NULL,
          version NUMBER(38,0) NOT NULL,
          ciphertext BINARY NOT NULL,
          metadata VARIANT,
          idempotency_key STRING,
          created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
          updated_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
          PRIMARY KEY (namespace, key, version)
        );

    Notes:
    - Snowflake does not enforce primary/unique constraints strictly; we implement
      idempotency explicitly and wrap writes into transactions.
    - Encryption is expected to be performed by OblivionVault before storing.
    """

    def __init__(
        self,
        config: SnowflakeAdapterConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._cfg = config
        self._logger = logger or _LOG
        self._table_fqn = _qname(config.database, config.schema, config.table)

    # ----- low-level connection helpers -----

    def _connect_sync(self):
        try:
            import snowflake.connector  # type: ignore
        except Exception as e:  # pragma: no cover
            raise StorageConnectionError(
                "snowflake-connector-python is required"
            ) from e

        kwargs: Dict[str, Any] = dict(
            account=self._cfg.account,
            user=self._cfg.user,
            role=self._cfg.role,
            warehouse=self._cfg.warehouse,
            database=self._cfg.database,
            schema=self._cfg.schema,
            login_timeout=self._cfg.login_timeout_s,
            network_timeout=self._cfg.network_timeout_s,
            session_parameters=self._cfg.session_parameters or {},
        )

        if self._cfg.authenticator:
            kwargs["authenticator"] = self._cfg.authenticator

        if self._cfg.auth_type == SnowflakeAuthType.PASSWORD:
            if not self._cfg.password:
                raise StorageConfigError("Password is required for auth_type=password")
            kwargs["password"] = (
                self._cfg.password.get_secret_value()
                if hasattr(self._cfg.password, "get_secret_value")
                else str(self._cfg.password)
            )
        else:
            if not self._cfg.private_key_path:
                raise StorageConfigError("private_key_path is required for auth_type=private_key")
            pk_bytes = _load_private_key(
                self._cfg.private_key_path,
                self._cfg.private_key_passphrase.get_secret_value()  # type: ignore
                if isinstance(self._cfg.private_key_passphrase, SecretStr)
                else None
            )
            kwargs["private_key"] = pk_bytes

        try:
            conn = snowflake.connector.connect(**kwargs)
        except Exception as e:  # pragma: no cover
            raise StorageConnectionError(f"Failed to connect to Snowflake: {e}") from e
        return conn

    @asynccontextmanager
    async def _connection(self):
        conn = await _to_thread(self._connect_sync)
        try:
            yield conn
        finally:
            try:
                await _to_thread(conn.close)
            except Exception:
                self._logger.debug("Snowflake connection close failed", exc_info=True)

    async def _exec(
        self,
        conn,
        sql: str,
        params: Optional[Union[Tuple, List, Dict[str, Any]]] = None,
        fetch: Optional[str] = None,  # None | "one" | "all"
    ):
        """
        Execute SQL with parameters. `fetch` controls returning rows.
        """
        self._logger.debug("Executing SQL", extra={"sql": sql})
        def _run():
            with conn.cursor() as cur:
                cur.execute(sql, params or ())
                if fetch == "one":
                    return cur.fetchone()
                if fetch == "all":
                    return cur.fetchall()
                return None
        return await _to_thread(_run)

    async def _begin(self, conn):
        await self._exec(conn, "BEGIN")

    async def _commit(self, conn):
        await self._exec(conn, "COMMIT")

    async def _rollback(self, conn):
        try:
            await self._exec(conn, "ROLLBACK")
        except Exception:
            self._logger.warning("Rollback failed", exc_info=True)

    # ----- public API -----

    async def ensure_initialized(self) -> None:
        """
        Create schema and table if they do not exist. Idempotent.
        """
        cfg = self._cfg
        schema_fqn = f"{_quote_ident(cfg.database)}.{_quote_ident(cfg.schema)}"
        create_schema = f"CREATE SCHEMA IF NOT EXISTS {schema_fqn}"
        create_table = f"""
        CREATE TABLE IF NOT EXISTS {self._table_fqn} (
          namespace STRING NOT NULL,
          key STRING NOT NULL,
          version NUMBER(38,0) NOT NULL,
          ciphertext BINARY NOT NULL,
          metadata VARIANT,
          idempotency_key STRING,
          created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
          updated_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
          PRIMARY KEY (namespace, key, version)
        )
        """
        async with self._connection() as conn:
            await self._exec(conn, create_schema)
            await self._exec(conn, create_table)

    async def health_check(self) -> bool:
        """
        Simple connectivity check.
        """
        try:
            async with self._connection() as conn:
                row = await self._exec(conn, "SELECT 1", fetch="one")
                return bool(row and row[0] == 1)
        except Exception as e:
            self._logger.error("Health check failed: %s", e, extra={"event": "health_check_failed"})
            return False

    async def write_secret(
        self,
        namespace: str,
        key: str,
        ciphertext: bytes,
        metadata: Optional[Dict[str, Any]] = None,
        *,
        version: Optional[int] = None,
        idempotency_key: Optional[str] = None,
        overwrite: bool = False,
    ) -> SecretRecord:
        """
        Store a secret version. If version is None, auto-increment last version + 1.
        Idempotency: if idempotency_key provided and seen before, returns existing record.
        """
        meta_json = _json_dumps_compact(metadata or {})
        async with self._connection() as conn:
            await self._begin(conn)
            try:
                # 1) Idempotency fast-path
                if idempotency_key:
                    row = await self._exec(
                        conn,
                        f"""
                        SELECT namespace, key, version, ciphertext, metadata, TO_CHAR(created_at), TO_CHAR(updated_at), idempotency_key
                        FROM {self._table_fqn}
                        WHERE idempotency_key = %s
                        """,
                        (idempotency_key,),
                        fetch="one",
                    )
                    if row:
                        await self._commit(conn)
                        return SecretRecord(
                            namespace=row[0],
                            key=row[1],
                            version=int(row[2]),
                            ciphertext=row[3],
                            metadata=row[4] if isinstance(row[4], dict) else json.loads(row[4]),
                            created_at=row[5],
                            updated_at=row[6],
                            idempotency_key=row[7],
                        )

                # 2) Determine version
                if version is None:
                    row = await self._exec(
                        conn,
                        f"""
                        SELECT COALESCE(MAX(version), 0) + 1
                        FROM {self._table_fqn}
                        WHERE namespace = %s AND key = %s
                        """,
                        (namespace, key),
                        fetch="one",
                    )
                    next_version = int(row[0]) if row and row[0] is not None else 1
                else:
                    next_version = int(version)

                # 3) Conflict check (if overwrite is False)
                if not overwrite:
                    row = await self._exec(
                        conn,
                        f"""
                        SELECT 1
                        FROM {self._table_fqn}
                        WHERE namespace = %s AND key = %s AND version = %s
                        """,
                        (namespace, key, next_version),
                        fetch="one",
                    )
                    if row:
                        raise StorageConflictError(
                            f"Secret already exists: {namespace}/{key} v{next_version}"
                        )

                # 4) Insert or Update
                if overwrite:
                    # Update if exists, else insert
                    await self._exec(
                        conn,
                        f"""
                        MERGE INTO {self._table_fqn} t
                        USING (
                          SELECT %s AS namespace,
                                 %s AS key,
                                 %s AS version,
                                 %s AS ciphertext,
                                 PARSE_JSON(%s) AS metadata,
                                 %s AS idempotency_key
                        ) s
                        ON t.namespace = s.namespace AND t.key = s.key AND t.version = s.version
                        WHEN MATCHED THEN UPDATE SET
                          ciphertext = s.ciphertext,
                          metadata = s.metadata,
                          idempotency_key = s.idempotency_key,
                          updated_at = CURRENT_TIMESTAMP()
                        WHEN NOT MATCHED THEN INSERT
                          (namespace, key, version, ciphertext, metadata, idempotency_key)
                          VALUES (s.namespace, s.key, s.version, s.ciphertext, s.metadata, s.idempotency_key)
                        """,
                        (namespace, key, next_version, ciphertext, meta_json, idempotency_key),
                    )
                else:
                    # Insert-only
                    await self._exec(
                        conn,
                        f"""
                        INSERT INTO {self._table_fqn}
                          (namespace, key, version, ciphertext, metadata, idempotency_key)
                        SELECT %s, %s, %s, %s, PARSE_JSON(%s), %s
                        """,
                        (namespace, key, next_version, ciphertext, meta_json, idempotency_key),
                    )

                # 5) Return stored record
                row = await self._exec(
                    conn,
                    f"""
                    SELECT namespace, key, version, ciphertext, metadata, TO_CHAR(created_at), TO_CHAR(updated_at), idempotency_key
                    FROM {self._table_fqn}
                    WHERE namespace = %s AND key = %s AND version = %s
                    """,
                    (namespace, key, next_version),
                    fetch="one",
                )
                await self._commit(conn)
                if not row:
                    raise StorageError("Write succeeded but record not found afterwards")

                return SecretRecord(
                    namespace=row[0],
                    key=row[1],
                    version=int(row[2]),
                    ciphertext=row[3],
                    metadata=row[4] if isinstance(row[4], dict) else json.loads(row[4]),
                    created_at=row[5],
                    updated_at=row[6],
                    idempotency_key=row[7],
                )
            except Exception:
                await self._rollback(conn)
                raise

    async def read_secret(
        self,
        namespace: str,
        key: str,
        version: Optional[int] = None,
    ) -> SecretRecord:
        """
        Read a secret. If version is None, fetch the latest version.
        """
        async with self._connection() as conn:
            if version is None:
                row = await self._exec(
                    conn,
                    f"""
                    SELECT namespace, key, version, ciphertext, metadata, TO_CHAR(created_at), TO_CHAR(updated_at), idempotency_key
                    FROM {self._table_fqn}
                    WHERE namespace = %s AND key = %s
                    QUALIFY ROW_NUMBER() OVER (PARTITION BY namespace, key ORDER BY version DESC) = 1
                    """,
                    (namespace, key),
                    fetch="one",
                )
            else:
                row = await self._exec(
                    conn,
                    f"""
                    SELECT namespace, key, version, ciphertext, metadata, TO_CHAR(created_at), TO_CHAR(updated_at), idempotency_key
                    FROM {self._table_fqn}
                    WHERE namespace = %s AND key = %s AND version = %s
                    """,
                    (namespace, key, int(version)),
                    fetch="one",
                )

            if not row:
                raise StorageNotFoundError(f"Secret not found: {namespace}/{key} (v={version or 'latest'})")

            return SecretRecord(
                namespace=row[0],
                key=row[1],
                version=int(row[2]),
                ciphertext=row[3],
                metadata=row[4] if isinstance(row[4], dict) else json.loads(row[4]),
                created_at=row[5],
                updated_at=row[6],
                idempotency_key=row[7],
            )

    async def list_secrets(
        self,
        namespace: str,
        *,
        prefix: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        latest_only: bool = True,
    ) -> List[SecretRecord]:
        """
        List secrets in a namespace. If latest_only=True, returns only latest version per key.
        """
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)

        async with self._connection() as conn:
            if latest_only:
                if prefix:
                    sql = f"""
                    WITH ranked AS (
                      SELECT namespace, key, version, ciphertext, metadata, TO_CHAR(created_at) as created_at, TO_CHAR(updated_at) as updated_at, idempotency_key,
                             ROW_NUMBER() OVER (PARTITION BY namespace, key ORDER BY version DESC) AS rn
                      FROM {self._table_fqn}
                      WHERE namespace = %s AND key ILIKE %s
                    )
                    SELECT namespace, key, version, ciphertext, metadata, created_at, updated_at, idempotency_key
                    FROM ranked WHERE rn = 1
                    ORDER BY key
                    LIMIT {limit} OFFSET {offset}
                    """
                    params = (namespace, f"{prefix}%")
                else:
                    sql = f"""
                    WITH ranked AS (
                      SELECT namespace, key, version, ciphertext, metadata, TO_CHAR(created_at) as created_at, TO_CHAR(updated_at) as updated_at, idempotency_key,
                             ROW_NUMBER() OVER (PARTITION BY namespace, key ORDER BY version DESC) AS rn
                      FROM {self._table_fqn}
                      WHERE namespace = %s
                    )
                    SELECT namespace, key, version, ciphertext, metadata, created_at, updated_at, idempotency_key
                    FROM ranked WHERE rn = 1
                    ORDER BY key
                    LIMIT {limit} OFFSET {offset}
                    """
                    params = (namespace,)
            else:
                if prefix:
                    sql = f"""
                    SELECT namespace, key, version, ciphertext, metadata, TO_CHAR(created_at), TO_CHAR(updated_at), idempotency_key
                    FROM {self._table_fqn}
                    WHERE namespace = %s AND key ILIKE %s
                    ORDER BY key, version DESC
                    LIMIT {limit} OFFSET {offset}
                    """
                    params = (namespace, f"{prefix}%")
                else:
                    sql = f"""
                    SELECT namespace, key, version, ciphertext, metadata, TO_CHAR(created_at), TO_CHAR(updated_at), idempotency_key
                    FROM {self._table_fqn}
                    WHERE namespace = %s
                    ORDER BY key, version DESC
                    LIMIT {limit} OFFSET {offset}
                    """
                    params = (namespace,)

            rows = await self._exec(conn, sql, params, fetch="all") or []

        result: List[SecretRecord] = []
        for r in rows:
            result.append(
                SecretRecord(
                    namespace=r[0],
                    key=r[1],
                    version=int(r[2]),
                    ciphertext=r[3],
                    metadata=r[4] if isinstance(r[4], dict) else json.loads(r[4]),
                    created_at=r[5],
                    updated_at=r[6],
                    idempotency_key=r[7],
                )
            )
        return result

    async def delete_secret(
        self,
        namespace: str,
        key: str,
        *,
        version: Optional[int] = None,
    ) -> int:
        """
        Delete a secret. If version is None, delete all versions of the key.
        Returns number of rows deleted.
        """
        async with self._connection() as conn:
            await self._begin(conn)
            try:
                if version is None:
                    sql = f"DELETE FROM {self._table_fqn} WHERE namespace = %s AND key = %s"
                    params = (namespace, key)
                else:
                    sql = f"DELETE FROM {self._table_fqn} WHERE namespace = %s AND key = %s AND version = %s"
                    params = (namespace, key, int(version))

                def _run():
                    with conn.cursor() as cur:
                        cur.execute(sql, params)
                        return cur.rowcount

                deleted = await _to_thread(_run)
                await self._commit(conn)
                return int(deleted or 0)
            except Exception:
                await self._rollback(conn)
                raise
