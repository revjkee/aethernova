import subprocess
import logging
import os
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

# === TeslaAI Test Pipeline Engine v3.7 ===
# Agents: PyTestRunner, CoverageAnalyzer, TestProfiler, AlertOnFailure, TraceCollector,
# AgentCoverageMapper, TestSorter, RetryHandler, GitTracker, MutationTrigger,
# IsolationExecutor, LLMValidator, ScenarioInjector, SandboxRunner,
# RedTagVerifier, CodeDiffBinder, WatchdogTimer, ErrorClassifier,
# LogExporter, SlackNotifier
# MetaGenerals: Guardian, Evolver, Architectus

logger = logging.getLogger("test_pipeline")
logger.setLevel(logging.INFO)

class TestPipeline:
    def __init__(
        self,
        test_dirs: List[str] = ["llmops/tests", "agent-mash/tests", "backend/ci/chaos-testing"],
        report_dir: str = "backend/ci/test_reports",
        retries: int = 1
    ):
        self.test_dirs = test_dirs
        self.report_dir = Path(report_dir)
        self.retries = retries
        self.results: List[Dict[str, Any]] = []

        self.report_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Initialized TestPipeline with dirs: {self.test_dirs}")

    def run(self):
        for test_dir in self.test_dirs:
            for attempt in range(1, self.retries + 2):
                logger.info(f"Running tests in {test_dir} (attempt {attempt})")
                result = self._run_pytest(test_dir, attempt)
                self.results.append(result)
                if result["exit_code"] == 0:
                    break
                elif attempt <= self.retries:
                    logger.warning(f"Retrying {test_dir}...")
                else:
                    logger.error(f"Test failed after {attempt} attempts: {test_dir}")

        self._summarize()
        self._export()

    def _run_pytest(self, test_dir: str, attempt: int) -> Dict[str, Any]:
        timestamp = int(time.time())
        report_file = self.report_dir / f"{Path(test_dir).name}_attempt{attempt}_{timestamp}.json"
        cmd = [
            "pytest",
            test_dir,
            "--tb=short",
            "--json-report",
            f"--json-report-file={report_file}",
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
            logger.info(proc.stdout)
            if proc.returncode != 0:
                logger.warning(proc.stderr)
            return {
                "dir": test_dir,
                "attempt": attempt,
                "exit_code": proc.returncode,
                "report_path": str(report_file),
            }
        except Exception as e:
            logger.exception(f"Failed to run tests in {test_dir}")
            return {
                "dir": test_dir,
                "attempt": attempt,
                "exit_code": -1,
                "error": str(e),
            }

    def _summarize(self):
        summary = {
            "total_tests": len(self.results),
            "failures": sum(1 for r in self.results if r["exit_code"] != 0),
            "successful": sum(1 for r in self.results if r["exit_code"] == 0),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        logger.info(f"Test Summary: {summary}")

    def _export(self):
        summary_path = self.report_dir / "summary.json"
        try:
            import json
            with open(summary_path, "w") as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Exported test results to {summary_path}")
        except Exception as e:
            logger.error(f"Failed to export test summary: {e}")
