# llmops/dashboard/usage_stats_collector.py

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from llmops.core.config import settings
from llmops.db.models.usage import UsageEvent
from llmops.db.session import get_async_session
from llmops.core.security.ratelimit import is_suspicious_usage
from llmops.core.alerting.notifier import send_alert
from llmops.utils.time import get_utc_now

logger = logging.getLogger(__name__)


class UsageStatsCollector:
    def __init__(self):
        self.redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        self.queue_key = settings.USAGE_STATS_REDIS_QUEUE
        self.batch_size = settings.USAGE_STATS_BATCH_SIZE
        self.flush_interval = settings.USAGE_STATS_FLUSH_INTERVAL_SEC
        self.lock_key = "usage_collector:lock"
        self.lock_ttl = 30  # seconds

    async def collect_loop(self):
        while True:
            try:
                await self.process_batch()
            except Exception as e:
                logger.exception(f"Usage collector failed: {e}")
            await asyncio.sleep(self.flush_interval)

    async def process_batch(self):
        async with self.redis.pipeline(transaction=True) as pipe:
            entries = await self.redis.lrange(self.queue_key, 0, self.batch_size - 1)
            if not entries:
                return

            await self.redis.ltrim(self.queue_key, len(entries), -1)

        parsed_events = [self._parse_event(entry) for entry in entries if entry]
        async with get_async_session() as session:
            await self._persist_events(session, parsed_events)

    def _parse_event(self, raw: str) -> Dict[str, Any]:
        try:
            import json
            event = json.loads(raw)
            event['received_at'] = get_utc_now().isoformat()
            return event
        except Exception:
            logger.warning("Invalid usage event format")
            return {}

    async def _persist_events(self, session: AsyncSession, events: list[Dict[str, Any]]):
        for event in events:
            if not event:
                continue

            usage = UsageEvent(
                user_id=event.get("user_id"),
                model=event.get("model"),
                tokens_used=event.get("tokens_used", 0),
                latency_ms=event.get("latency_ms", 0),
                success=event.get("success", True),
                received_at=event.get("received_at"),
                request_id=event.get("request_id"),
                metadata=event.get("metadata", {}),
            )

            if is_suspicious_usage(usage):
                logger.warning(f"Suspicious usage: {usage}")
                await send_alert("Suspicious LLM usage detected", usage.dict())

            session.add(usage)

        await session.commit()
