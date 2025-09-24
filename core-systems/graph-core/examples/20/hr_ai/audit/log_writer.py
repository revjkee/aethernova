import sqlite3
from datetime import datetime
from .audit_schema import DB_PATH

def write_audit_log(event_type, actor, subject, action, result, source_ip=None, meta="{}"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        INSERT INTO audit_logs (
            timestamp, event_type, actor, subject, action, result, source_ip, meta
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(),
        event_type,
        actor,
        subject,
        action,
        result,
        source_ip,
        meta
    ))

    conn.commit()
    conn.close()
