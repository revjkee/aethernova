# forgemind-core/payload_lab/autopayload_sim.py

import os
import subprocess
import uuid
import tempfile
import time
import logging
import threading
from typing import List, Dict, Optional, Any

logger = logging.getLogger("autopayload_sim")
logger.setLevel(logging.DEBUG)

class PayloadExecutionResult:
    def __init__(self, success: bool, output: str, errors: str, return_code: int, duration: float):
        self.success = success
        self.output = output
        self.errors = errors
        self.return_code = return_code
        self.duration = duration

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "errors": self.errors,
            "return_code": self.return_code,
            "duration": self.duration
        }

class AutoPayloadSimulator:
    def __init__(self, sandbox_cmd_prefix: Optional[List[str]] = None, timeout: float = 5.0):
        self.sandbox_prefix = sandbox_cmd_prefix or ["firejail", "--quiet", "--net=none", "--private"]
        self.timeout = timeout

    def _run_payload(self, payload_script: str) -> PayloadExecutionResult:
        temp_dir = tempfile.mkdtemp(prefix="sim_")
        payload_path = os.path.join(temp_dir, f"payload_{uuid.uuid4().hex}.sh")
        with open(payload_path, "w") as f:
            f.write(payload_script)
        os.chmod(payload_path, 0o700)

        command = self.sandbox_prefix + [payload_path]
        start_time = time.time()

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            end_time = time.time()
            result = PayloadExecutionResult(
                success=(proc.returncode == 0),
                output=proc.stdout.strip(),
                errors=proc.stderr.strip(),
                return_code=proc.returncode,
                duration=round(end_time - start_time, 4)
            )
        except subprocess.TimeoutExpired:
            result = PayloadExecutionResult(
                success=False,
                output="",
                errors="Timeout",
                return_code=-1,
                duration=self.timeout
            )
        except Exception as e:
            result = PayloadExecutionResult(
                success=False,
                output="",
                errors=str(e),
                return_code=-2,
                duration=self.timeout
            )

        logger.debug(f"[SIM] Payload result: {result.to_dict()}")
        return result

    def simulate_payload_batch(self, payloads: List[str]) -> List[PayloadExecutionResult]:
        results = []
        for i, script in enumerate(payloads):
            logger.info(f"[SIM] Running payload {i+1}/{len(payloads)}")
            result = self._run_payload(script)
            results.append(result)
        return results

    def validate_results(self, results: List[PayloadExecutionResult], min_success_ratio: float = 0.5) -> bool:
        successful = sum(1 for r in results if r.success)
        ratio = successful / len(results) if results else 0
        logger.info(f"[SIM] Success ratio: {ratio}")
        return ratio >= min_success_ratio

    def export_simulation_report(self, results: List[PayloadExecutionResult]) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in results]

    def run_async_simulations(self, payloads: List[str], callback: Optional[Any] = None):
        def runner():
            results = self.simulate_payload_batch(payloads)
            if callback:
                callback(results)
        thread = threading.Thread(target=runner)
        thread.start()
        return thread
