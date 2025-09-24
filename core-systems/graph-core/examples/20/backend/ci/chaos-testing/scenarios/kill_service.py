import os
import signal
import subprocess
import logging

logger = logging.getLogger("chaos.kill_service")
logger.setLevel(logging.INFO)


def find_processes_by_name(name: str):
    try:
        result = subprocess.check_output(["pgrep", "-f", name]).decode().split()
        return [int(pid) for pid in result]
    except subprocess.CalledProcessError:
        return []


def terminate_process(pid: int, sig=signal.SIGTERM):
    try:
        os.kill(pid, sig)
        logger.info(f"Process {pid} terminated with signal {sig}.")
    except ProcessLookupError:
        logger.warning(f"Process {pid} not found.")
    except PermissionError:
        logger.error(f"Permission denied when terminating process {pid}.")
    except Exception as e:
        logger.exception(f"Error terminating process {pid}: {e}")


def run(params):
    name = params.get("process_name")
    sig = getattr(signal, params.get("signal", "SIGTERM"), signal.SIGTERM)

    if not name:
        logger.error("No process_name specified in parameters.")
        return

    pids = find_processes_by_name(name)
    if not pids:
        logger.info(f"No running processes found matching: {name}")
        return

    for pid in pids:
        terminate_process(pid, sig)


def revert(params):
    logger.info("No revert action defined for kill_service chaos event.")


# Метаданные для регистрации сценария в движке хаоса
metadata = {
    "name": "kill_service",
    "description": "Forcefully terminate a process by name.",
    "parameters": {
        "process_name": "Name of the process to kill",
        "signal": "Signal to send (SIGTERM or SIGKILL)"
    }
}
