import sqlite3
from .audit_schema import DB_PATH

def query_logs(limit=100, actor_filter=None, action_filter=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    base_query = "SELECT * FROM audit_logs"
    conditions = []
    values = []

    if actor_filter:
        conditions.append("actor = ?")
        values.append(actor_filter)
    if action_filter:
        conditions.append("action = ?")
        values.append(action_filter)

    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)

    base_query += " ORDER BY timestamp DESC LIMIT ?"
    values.append(limit)

    c.execute(base_query, values)
    rows = c.fetchall()
    conn.close()
    return rows
