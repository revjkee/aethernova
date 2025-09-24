import os
import subprocess
import uuid
import time
import shutil
import tempfile
import logging
from pathlib import Path

from testground.sandbox.utils import (
    setup_apparmor_profile,
    teardown_apparmor_profile,
    mount_overlayfs,
    unmount_overlayfs,
    trace_syscalls,
    collect_logs,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sandbox_runner")

class SandboxRunner:
    def __init__(self, payload_path: str, timeout: int = 30):
        self.payload_path = Path(payload_path).resolve()
        self.timeout = timeout
        self.session_id = f"sandbox-{uuid.uuid4()}"
        self.sandbox_root = Path(f"/tmp/forgemind_sandbox/{self.session_id}")
        self.workdir = self.sandbox_root / "rootfs"
        self.logs_dir = self.sandbox_root / "logs"
        self.overlay_dirs = {}

    def _prepare_environment(self):
        logger.info("Preparing sandbox environment...")
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.workdir, exist_ok=True)
        self.overlay_dirs = mount_overlayfs(self.workdir)

        setup_apparmor_profile(self.session_id)

    def _run_payload(self):
        exec_path = self.workdir / "bin" / "sandbox_exec.sh"
        shutil.copy2(self.payload_path, exec_path)
        os.chmod(exec_path, 0o700)

        logger.info("Executing payload in sandbox...")
        try:
            result = subprocess.run(
                ["firejail", f"--profile={self.session_id}", str(exec_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                cwd=str(self.workdir)
            )
            logger.info(f"Execution completed: {result.returncode}")
            with open(self.logs_dir / "stdout.log", "wb") as f:
                f.write(result.stdout)
            with open(self.logs_dir / "stderr.log", "wb") as f:
                f.write(result.stderr)
        except subprocess.TimeoutExpired:
            logger.warning("Payload execution timed out.")
            with open(self.logs_dir / "stderr.log", "a") as f:
                f.write(b"\nExecution timed out.")

    def _finalize(self):
        logger.info("Finalizing sandbox...")
        collect_logs(self.sandbox_root)
        trace_syscalls(self.session_id, self.logs_dir)
        teardown_apparmor_profile(self.session_id)
        unmount_overlayfs(self.overlay_dirs)
        shutil.rmtree(self.sandbox_root, ignore_errors=True)

    def run(self):
        try:
            self._prepare_environment()
            self._run_payload()
        finally:
            self._finalize()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run payload in sandbox.")
    parser.add_argument("payload_path", help="Path to executable payload")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    args = parser.parse_args()

    runner = SandboxRunner(args.payload_path, args.timeout)
    runner.run()
