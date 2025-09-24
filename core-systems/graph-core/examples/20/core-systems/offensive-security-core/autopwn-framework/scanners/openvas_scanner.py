import asyncio
import logging
from typing import List, Dict, Optional
from aiohttp import ClientSession
from datetime import datetime
from uuid import uuid4

from autopwn_framework.utils.gvm_client import GVMClient
from autopwn_framework.models.vuln import VulnerabilityReport

logger = logging.getLogger("openvas_scanner")
logger.setLevel(logging.INFO)

class OpenVASScanner:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client: Optional[GVMClient] = None
        self.session_id: Optional[str] = None

    async def connect(self):
        self.client = GVMClient(self.host, self.port)
        await self.client.connect()
        self.session_id = await self.client.authenticate(self.username, self.password)
        logger.info("Authenticated with OpenVAS. Session ID: %s", self.session_id)

    async def disconnect(self):
        if self.client:
            await self.client.disconnect()
            logger.info("Disconnected from OpenVAS")

    async def scan_target(self, target_ip: str, name: Optional[str] = None) -> VulnerabilityReport:
        if not self.client:
            raise RuntimeError("Not connected to OpenVAS")

        target_name = name or f"Target-{uuid4()}"
        logger.info("Creating target for %s", target_ip)
        target_id = await self.client.create_target(name=target_name, hosts=target_ip)

        logger.info("Creating task for %s", target_name)
        task_id = await self.client.create_task(name=f"Scan-{target_name}", target_id=target_id)

        logger.info("Starting scan task")
        report_id = await self.client.start_task(task_id)

        logger.info("Waiting for scan to complete...")
        await self._wait_for_completion(task_id)

        logger.info("Fetching report...")
        report = await self.client.get_report(report_id)
        parsed_report = self._parse_report(report, target_ip)

        return parsed_report

    async def _wait_for_completion(self, task_id: str, timeout: int = 1800, poll_interval: int = 10):
        start_time = datetime.now()
        while (datetime.now() - start_time).total_seconds() < timeout:
            status = await self.client.get_task_status(task_id)
            logger.info("Scan status: %s", status)
            if status.lower() == "done":
                return
            await asyncio.sleep(poll_interval)
        raise TimeoutError("OpenVAS scan timed out")

    def _parse_report(self, report_data: dict, target_ip: str) -> VulnerabilityReport:
        issues = []
        for result in report_data.get("results", []):
            severity = float(result.get("severity", 0.0))
            name = result.get("name", "Unnamed")
            description = result.get("description", "No description")
            cve = result.get("cve", [])
            issues.append({
                "name": name,
                "description": description,
                "severity": severity,
                "cve": cve,
                "host": target_ip
            })

        return VulnerabilityReport(
            scanner="OpenVAS",
            target=target_ip,
            issues=issues,
            timestamp=datetime.utcnow().isoformat()
        )

# Optional test entrypoint for standalone runs
if __name__ == "__main__":
    import argparse
    from autopwn_framework.utils.logger import configure_logger

    configure_logger()

    async def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("host")
        parser.add_argument("port", type=int)
        parser.add_argument("username")
        parser.add_argument("password")
        parser.add_argument("target_ip")
        args = parser.parse_args()

        scanner = OpenVASScanner(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password
        )

        await scanner.connect()
        try:
            report = await scanner.scan_target(args.target_ip)
            print(report.json(indent=2))
        finally:
            await scanner.disconnect()

    asyncio.run(main())
