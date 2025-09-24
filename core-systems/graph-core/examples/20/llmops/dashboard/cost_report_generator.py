import os
import logging
import datetime
from typing import Dict, List, Optional
from decimal import Decimal
from pydantic import BaseModel, Field
from zoneinfo import ZoneInfo

from core.llm.billing import get_costs_per_provider
from core.utils.currency import convert_currency
from core.storage.db import CostReportDB
from core.monitoring.alerts import AlertDispatcher
from core.config import settings
from core.utils.anomaly_detection import detect_cost_anomaly

logger = logging.getLogger("llmops.dashboard.cost_report_generator")
logger.setLevel(logging.INFO)

class ProviderCost(BaseModel):
    provider: str
    model: str
    usage_tokens: int
    cost_usd: Decimal
    currency: str = "USD"
    timestamp: datetime.datetime

class DailyCostSummary(BaseModel):
    date: datetime.date
    total_cost_usd: Decimal
    total_cost_native: Decimal
    native_currency: str
    provider_costs: List[ProviderCost]

class CostReportGenerator:
    def __init__(
        self,
        db: CostReportDB,
        alert_dispatcher: Optional[AlertDispatcher] = None,
        default_currency: str = "USD"
    ):
        self.db = db
        self.alert_dispatcher = alert_dispatcher or AlertDispatcher()
        self.default_currency = default_currency
        self.timezone = ZoneInfo(settings.TIMEZONE)

    def collect_cost_data(self) -> List[ProviderCost]:
        logger.info("Collecting LLM cost data from all providers...")
        raw_cost_data = get_costs_per_provider()
        results = []

        for entry in raw_cost_data:
            try:
                cost_record = ProviderCost(
                    provider=entry["provider"],
                    model=entry["model"],
                    usage_tokens=entry["tokens"],
                    cost_usd=Decimal(entry["cost_usd"]),
                    currency=entry.get("currency", "USD"),
                    timestamp=entry.get("timestamp", datetime.datetime.now(tz=self.timezone))
                )
                results.append(cost_record)
            except Exception as e:
                logger.warning(f"Failed to parse provider entry {entry}: {e}")

        logger.info(f"Collected {len(results)} cost records.")
        return results

    def generate_daily_report(self, provider_costs: List[ProviderCost]) -> DailyCostSummary:
        today = datetime.datetime.now(tz=self.timezone).date()
        logger.info(f"Generating daily cost summary for {today}...")

        total_cost_usd = sum(p.cost_usd for p in provider_costs)
        native_currency = settings.NATIVE_CURRENCY
        total_cost_native = convert_currency(total_cost_usd, "USD", native_currency)

        summary = DailyCostSummary(
            date=today,
            total_cost_usd=total_cost_usd,
            total_cost_native=total_cost_native,
            native_currency=native_currency,
            provider_costs=provider_costs
        )

        logger.info(f"Summary: {summary.total_cost_usd} USD ({summary.total_cost_native} {native_currency})")
        return summary

    def save_report(self, report: DailyCostSummary) -> None:
        logger.info("Saving cost report to database...")
        self.db.save_daily_report(report.dict())

    def check_and_alert(self, report: DailyCostSummary) -> None:
        logger.info("Running anomaly detection on daily report...")
        if detect_cost_anomaly(report.total_cost_usd):
            message = (
                f"⚠️ Anomaly Detected: Daily cost {report.total_cost_usd:.2f} USD "
                f"exceeds threshold.\nProviders involved: "
                + ", ".join(set([p.provider for p in report.provider_costs]))
            )
            self.alert_dispatcher.send_alert(message)

    def run(self) -> None:
        logger.info("Starting cost report generation job...")
        provider_costs = self.collect_cost_data()
        report = self.generate_daily_report(provider_costs)
        self.save_report(report)
        self.check_and_alert(report)
        logger.info("Cost report generation job complete.")

# Entry point for CLI/crontab
if __name__ == "__main__":
    db = CostReportDB()
    generator = CostReportGenerator(db=db)
    generator.run()
