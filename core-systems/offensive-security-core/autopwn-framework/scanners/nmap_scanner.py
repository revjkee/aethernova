import asyncio
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from subprocess import PIPE, STDOUT, CalledProcessError, create_subprocess_exec

from autopwn_core.config import settings
from autopwn_core.models.scan_result import ScanResult
from autopwn_core.utils.sanitize import sanitize_nmap_args
from autopwn_core.security.throttle import throttle_scan_rate
from autopwn_core.storage.result_store import store_scan_result


logger = logging.getLogger("nmap_scanner")


class NmapScanner:
    def __init__(self, rate_limit_per_minute: int = 60):
        self.rate_limit_per_minute = rate_limit_per_minute

    @throttle_scan_rate("nmap", rate_limit=60)
    async def scan(self, target: str, args: list[str] = None, scan_id: str = None) -> ScanResult:
        args = sanitize_nmap_args(args or ["-T4", "-sV", "-Pn", "-n"])
        output_file = Path(f"/tmp/nmap_scan_{scan_id or 'default'}.xml")

        nmap_cmd = ["nmap", "-oX", str(output_file), *args, target]
        logger.debug(f"Running Nmap: {' '.join(nmap_cmd)}")

        try:
            proc = await create_subprocess_exec(*nmap_cmd, stdout=PIPE, stderr=STDOUT)
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                logger.error(f"Nmap failed with exit code {proc.returncode}: {stdout.decode()}")
                raise CalledProcessError(proc.returncode, nmap_cmd)

            if not output_file.exists():
                raise FileNotFoundError("Nmap XML output not found")

            result = await self._parse_nmap_output(output_file)
            await store_scan_result(scan_id, result)
            return result

        except Exception as e:
            logger.exception(f"Nmap scan failed: {e}")
            raise

        finally:
            if output_file.exists():
                output_file.unlink()

    async def _parse_nmap_output(self, xml_file: Path) -> ScanResult:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts = []

            for host in root.findall("host"):
                addr_elem = host.find("address")
                ip = addr_elem.get("addr") if addr_elem is not None else "unknown"
                ports_info = []

                for port in host.findall(".//port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    state = port.find("state").get("state")
                    service_elem = port.find("service")
                    service = service_elem.get("name") if service_elem is not None else "unknown"
                    version = service_elem.get("version") if service_elem is not None else ""
                    ports_info.append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "version": version,
                    })

                hosts.append({
                    "ip": ip,
                    "ports": ports_info,
                })

            return ScanResult(scanner="nmap", hosts=hosts)

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            raise
