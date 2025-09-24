import subprocess
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger("NiktoScanner")
logger.setLevel(logging.DEBUG)

class NiktoScanner:
    def __init__(
        self,
        nikto_path: str = "nikto",
        output_dir: str = "scans/nikto",
        timeout: int = 300
    ):
        self.nikto_path = nikto_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout

    def scan(self, target_url: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Запуск сканирования с помощью Nikto.

        :param target_url: URL цели
        :param options: дополнительные параметры (dict)
        :return: результат в формате dict
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        output_file = self.output_dir / f"nikto_{timestamp}.json"
        base_cmd = [
            self.nikto_path,
            "-h", target_url,
            "-Format", "json",
            "-o", str(output_file)
        ]

        if options:
            if options.get("use_ssl"):
                base_cmd.extend(["-ssl"])
            if options.get("port"):
                base_cmd.extend(["-p", str(options["port"])])
            if options.get("user_agent"):
                base_cmd.extend(["-useragent", options["user_agent"]])
            if options.get("no_cache"):
                base_cmd.extend(["-nocache"])
            if options.get("debug"):
                base_cmd.extend(["-Display", "V"])

        try:
            logger.info(f"Starting Nikto scan on {target_url}")
            subprocess.run(
                base_cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout
            )
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                logger.debug(f"Nikto scan completed: {output_file}")
                return data
        except subprocess.TimeoutExpired:
            logger.error(f"Nikto scan timed out for {target_url}")
            return {"error": "timeout"}
        except subprocess.CalledProcessError as e:
            logger.error(f"Nikto scan failed: {e}")
            return {"error": "scan_failed", "details": e.stderr.decode()}
        except FileNotFoundError:
            logger.critical("Nikto not found. Ensure it is installed and in PATH.")
            return {"error": "nikto_not_found"}
        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON output from Nikto: {output_file}")
            return {"error": "invalid_json"}
        except Exception as e:
            logger.exception("Unexpected error during Nikto scan")
            return {"error": "unexpected_error", "details": str(e)}

    def is_installed(self) -> bool:
        """Проверяет, установлен ли Nikto в системе."""
        try:
            subprocess.run(
                [self.nikto_path, "-Version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return True
        except FileNotFoundError:
            return False
