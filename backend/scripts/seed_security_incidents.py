#!/usr/bin/env python3
"""Seed the security_incidents table with example data.

Run this from inside the backend container or where DATABASE_URL is available.
"""
import os
import asyncio
from datetime import datetime

from databases import Database
import sqlalchemy as sa

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///app/data/dev.db")

metadata = sa.MetaData()
security_incidents = sa.Table(
    "security_incidents",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("title", sa.String, nullable=False),
    sa.Column("severity", sa.String, nullable=True),
    sa.Column("description", sa.Text, nullable=True),
    sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
)


async def main():
    db = Database(DATABASE_URL)
    await db.connect()
    # ensure table exists (best effort)
    try:
        await db.execute(security_incidents.insert().values(title="Test incident: database seeded", severity="low", description="Seeded by script", created_at=datetime.utcnow()))
        await db.execute(security_incidents.insert().values(title="Another incident", severity="medium", description="Second seeded incident", created_at=datetime.utcnow()))
        print("Seeded 2 incidents")
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
"""Seed the security_incidents table with sample data.

This script is placed under backend/scripts so Dockerfile can copy it into the image
and it will be available at /app/scripts inside the running container.
"""
from datetime import datetime
import asyncio

from src.db import database
from src.models import security_incidents


async def seed():
    await database.connect()
    try:
        await database.execute(security_incidents.insert().values(title='Test incident: false positive', severity='low', description='Sample seeded incident', created_at=datetime.utcnow()))
        await database.execute(security_incidents.insert().values(title='Service interruption', severity='high', description='Simulated outage', created_at=datetime.utcnow()))
        print('Seeded sample security incidents')
    finally:
        await database.disconnect()


if __name__ == '__main__':
    asyncio.run(seed())
#!/usr/bin/env python3
"""Seed the security_incidents table with sample data.

Run inside the backend container or with the project's virtualenv.
"""
from datetime import datetime
import os
from src.db import database
from src.models import security_incidents


async def seed():
    await database.connect()
    try:
        await database.execute(security_incidents.insert().values(title='Test incident: false positive', severity='low', description='Sample seeded incident', created_at=datetime.utcnow()))
        await database.execute(security_incidents.insert().values(title='Service interruption', severity='high', description='Simulated outage', created_at=datetime.utcnow()))
        print('Seeded sample security incidents')
    finally:
        await database.disconnect()


if __name__ == '__main__':
    import asyncio

    asyncio.run(seed())
