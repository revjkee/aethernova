import asyncio
import json
import logging
import datetime
from typing import Callable, Dict, List, Optional

from autopwn_core.scheduler.cron import CronTrigger
from autopwn_core.bus.kafka_listener import KafkaAsyncListener
from autopwn_core.bus.redis_listener import RedisPubSubTrigger
from autopwn_core.classifiers.trigger_classifier import TriggerClassifier
from autopwn_core.orchestration.runner import launch_attack_scenario
from autopwn_core.shared.config import config
from autopwn_core.shared.utils import now_str

logger = logging.getLogger("autopwn.triggers")

class TriggerEngine:
    def __init__(self):
        self.kafka_listener = KafkaAsyncListener(topic="telemetry.security")
        self.redis_listener = RedisPubSubTrigger(channel="autopwn:trigger")
        self.cron_tasks: List[CronTrigger] = []
        self.classifier = TriggerClassifier()
        self.running = False

    async def start(self):
        self.running = True
        await asyncio.gather(
            self._start_cron_rules(),
            self._start_kafka_listener(),
            self._start_redis_listener()
        )

    async def _start_cron_rules(self):
        rules = config.get("trigger_rules.cron", [])
        for rule in rules:
            ct = CronTrigger(
                rule["cron"],
                callback=lambda: self._run_trigger(rule["scenario"], "cron", rule)
            )
            self.cron_tasks.append(ct)
            ct.start()
            logger.info(f"Started cron trigger for: {rule['scenario']}")

    async def _start_kafka_listener(self):
        async for message in self.kafka_listener.listen():
            try:
                event = json.loads(message.value)
                classification = self.classifier.classify_event(event)
                if classification and classification.get("scenario"):
                    await self._run_trigger(
                        scenario=classification["scenario"],
                        source="kafka",
                        metadata=classification
                    )
            except Exception as ex:
                logger.exception(f"Kafka trigger failed: {ex}")

    async def _start_redis_listener(self):
        async for event in self.redis_listener.listen():
            try:
                data = json.loads(event["data"])
                await self._run_trigger(
                    scenario=data["scenario"],
                    source="redis",
                    metadata=data
                )
            except Exception as ex:
                logger.exception(f"Redis trigger failed: {ex}")

    async def _run_trigger(self, scenario: str, source: str, metadata: Optional[Dict] = None):
        logger.info(f"[{now_str()}] Triggered scenario `{scenario}` from `{source}`")
        try:
            await launch_attack_scenario(scenario_name=scenario, metadata=metadata)
        except Exception as ex:
            logger.error(f"Failed to launch scenario {scenario}: {ex}")

    async def stop(self):
        self.running = False
        for cron in self.cron_tasks:
            cron.stop()
        await self.kafka_listener.stop()
        await self.redis_listener.stop()
        logger.info("TriggerEngine stopped")

# Entry point for isolated execution
if __name__ == "__main__":
    engine = TriggerEngine()
    asyncio.run(engine.start())
