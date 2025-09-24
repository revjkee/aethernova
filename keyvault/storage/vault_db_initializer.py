# keyvault/storage/vault_db_initializer.py

import os
import hashlib
import logging
import pysqlcipher3.dbapi2 as sql

from keyvault.config.vault_config_loader import get_storage_config

logger = logging.getLogger("vault_db_initializer")
logger.setLevel(logging.INFO)

DB_PATH = "keyvault/storage/vault_db.sqlite"
CONFIG = get_storage_config()
DB_KEY = CONFIG["encryption_key"]  # В формате HEX или из secure vault


def initialize_encrypted_db():
    """
    Создаёт и инициализирует зашифрованную SQLite-БД, если она отсутствует.
    """
    first_run = not os.path.exists(DB_PATH)
    conn = sql.connect(DB_PATH)
    cursor = conn.cursor()

    # Шифрование через SQLCipher
    cursor.execute(f"PRAGMA key = '{DB_KEY}'")
    cursor.execute("PRAGMA cipher_page_size = 4096")
    cursor.execute("PRAGMA kdf_iter = 64000")
    cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")
    cursor.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")

    if first_run:
        logger.info("Инициализация новой зашифрованной БД...")
        cursor.execute("""
        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL,
            metadata TEXT,
            scope TEXT DEFAULT 'global',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            actor_id TEXT,
            action TEXT,
            resource TEXT,
            context_hash TEXT,
            signature TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE config_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_type TEXT,
            checksum TEXT,
            version TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        logger.info("База данных успешно создана.")
    else:
        logger.info("Зашифрованная БД уже существует.")

    conn.commit()
    conn.close()
