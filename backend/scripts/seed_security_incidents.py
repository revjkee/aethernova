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
