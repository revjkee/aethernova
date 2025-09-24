import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "logs.db")

def initialize_audit_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            subject TEXT NOT NULL,
            action TEXT NOT NULL,
            result TEXT NOT NULL,
            source_ip TEXT,
            meta TEXT DEFAULT '{}'
        );
    """)

    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC);
    """)

    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_actor_subject ON audit_logs (actor, subject);
    """)

    conn.commit()
    conn.close()
