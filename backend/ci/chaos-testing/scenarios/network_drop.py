import os
import logging
import subprocess
import time
import signal

logger = logging.getLogger("chaos.network_drop")
logger.setLevel(logging.INFO)

class NetworkDropScenario:
    def __init__(self, target_interface: str = "eth0", duration: int = 10):
        self.target_interface = target_interface
        self.duration = duration

    def execute(self):
        logger.info(f"[NetworkDrop] Disabling interface: {self.target_interface} for {self.duration} seconds")
        if not self._interface_exists():
            logger.warning(f"Interface {self.target_interface} not found.")
            return False

        if not self._set_interface_state("down"):
            logger.error("Failed to disable interface.")
            return False

        time.sleep(self.duration)

        logger.info(f"[NetworkDrop] Restoring interface: {self.target_interface}")
        if not self._set_interface_state("up"):
            logger.error("Failed to restore interface.")
            return False

        logger.info("[NetworkDrop] Completed successfully")
        return True

    def _interface_exists(self):
        try:
            result = subprocess.run(["ip", "link", "show", self.target_interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error checking interface: {e}")
            return False

    def _set_interface_state(self, state: str):
        try:
            result = subprocess.run(["sudo", "ip", "link", "set", self.target_interface, state], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error setting interface {state}: {e}")
            return False

# Register scenario with chaos engine

def register(engine):
    engine.register_event(
        name="network_drop",
        handler=lambda **kwargs: NetworkDropScenario(
            target_interface=kwargs.get("interface", "eth0"),
            duration=int(kwargs.get("duration", 10))
        ).execute
    )
