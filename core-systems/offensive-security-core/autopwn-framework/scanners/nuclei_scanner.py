import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

logger = logging.getLogger("NucleiScanner")
logger.setLevel(logging.DEBUG)


class NucleiScanner:
    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates_path: Optional[str] = None,
        output_dir: str = "scans/nuclei",
        timeout: int = 300
    ):
        self.nuclei_path = nuclei_path
        self.templates_path = templates_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout

    def scan(self, target: str, tags: Optional[List[str]] = None, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Запуск сканирования Nuclei по цели.

        :param target: URL/IP-цель
        :param tags: список тегов шаблонов (опционально)
        :param options: дополнительные опции Nuclei (dict)
        :return: результат сканирования
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        output_file = self.output_dir / f"nuclei_{timestamp}.json"

        base_cmd = [
            self.nuclei_path,
            "-target", target,
            "-json",
            "-o", str(output_file)
        ]

        if self.templates_path:
            base_cmd.extend(["-templates", self.templates_path])

        if tags:
            base_cmd.extend(["-tags", ",".join(tags)])

        if options:
            if options.get("severity"):
                base_cmd.extend(["-severity", ",".join(options["severity"])])
            if options.get("rate_limit"):
                base_cmd.extend(["-rl", str(options["rate_limit"])])
            if options.get("template_filter"):
                base_cmd.extend(["-t", options["template_filter"]])
            if options.get("proxy"):
                base_cmd.extend(["-proxy", options["proxy"]])
            if options.get("debug"):
                base_cmd.append("-debug")

        try:
            logger.info(f"Запуск Nuclei сканирования цели: {target}")
            subprocess.run(
                base_cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout
            )
            if not output_file.exists():
                logger.warning(f"Файл результатов {output_file} не найден")
                return {"error": "no_output"}

            with open(output_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                results = [self._parse_line_json(line) for line in lines if line.strip()]
                logger.info(f"Nuclei сканирование завершено, найдено {len(results)} уязвимостей")
                return {"results": results, "count": len(results)}
        except subprocess.TimeoutExpired:
            logger.error("Время выполнения Nuclei истекло")
            return {"error": "timeout"}
        except subprocess.CalledProcessError as e:
            logger.error(f"Nuclei ошибка выполнения: {e}")
            return {"error": "scan_failed", "details": e.stderr.decode()}
        except Exception as e:
            logger.exception("Неожиданная ошибка при запуске Nuclei")
            return {"error": "unexpected_error", "details": str(e)}

    @staticmethod
    def _parse_line_json(line: str) -> Dict[str, Any]:
        import json
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return {"invalid_json": line}

    def is_installed(self) -> bool:
        try:
            subprocess.run(
                [self.nuclei_path, "-version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return True
        except FileNotFoundError:
            return False
