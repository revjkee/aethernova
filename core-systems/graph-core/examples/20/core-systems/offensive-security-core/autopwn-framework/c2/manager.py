import threading
import logging
import time
from typing import Dict, Optional, Any, List
from uuid import uuid4

from c2.grpc_c2 import GRPCC2Handler
from c2.http_c2 import HTTPC2Handler
from c2.mqtt_c2 import MQTTC2Handler
from c2.dns_c2 import DNSC2Handler

from c2_profiles.loader import load_profiles
from core.logger import get_logger
from core.health_check import C2HealthChecker
from core.module_registry import ModuleRegistry
from secure_configs.secrets import decrypt_secret

logger = get_logger("C2Manager")


class C2Instance:
    def __init__(self, name: str, handler: Any, profile: Dict[str, Any]):
        self.id = str(uuid4())
        self.name = name
        self.handler = handler
        self.profile = profile
        self.active = False
        self.created_at = time.time()
        self.heartbeat = None

    def start(self):
        try:
            logger.info(f"Starting C2 instance {self.name} ({self.id})")
            self.handler.start()
            self.active = True
        except Exception as e:
            logger.exception(f"Failed to start C2 instance {self.name}: {e}")
            self.active = False

    def stop(self):
        try:
            logger.info(f"Stopping C2 instance {self.name} ({self.id})")
            self.handler.stop()
            self.active = False
        except Exception as e:
            logger.exception(f"Failed to stop C2 instance {self.name}: {e}")

    def status(self):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.handler.__class__.__name__,
            "active": self.active,
            "uptime": round(time.time() - self.created_at, 2),
            "heartbeat": self.heartbeat
        }


class C2Manager:
    def __init__(self):
        self.instances: Dict[str, C2Instance] = {}
        self.lock = threading.Lock()
        self.module_registry = ModuleRegistry()
        self.profiles = load_profiles()
        self.health_checker = C2HealthChecker()
        self._initialize_all()

    def _initialize_all(self):
        logger.info("Initializing all C2 instances from profiles...")
        for profile_name, profile in self.profiles.items():
            self.create_instance(profile_name, profile)

    def _get_handler(self, profile: Dict[str, Any]) -> Optional[Any]:
        c2_type = profile.get("type")
        if c2_type == "grpc":
            return GRPCC2Handler(profile)
        elif c2_type == "http":
            return HTTPC2Handler(profile)
        elif c2_type == "dns":
            return DNSC2Handler(profile)
        elif c2_type == "mqtt":
            return MQTTC2Handler(profile)
        else:
            logger.warning(f"Unknown C2 type: {c2_type}")
            return None

    def create_instance(self, name: str, profile: Dict[str, Any]) -> Optional[str]:
        with self.lock:
            if name in self.instances:
                logger.warning(f"C2 instance '{name}' already exists.")
                return None

            handler = self._get_handler(profile)
            if not handler:
                return None

            instance = C2Instance(name, handler, profile)
            instance.start()
            self.instances[name] = instance
            logger.info(f"C2 instance '{name}' created successfully.")
            return instance.id

    def stop_instance(self, name: str) -> bool:
        with self.lock:
            instance = self.instances.get(name)
            if not instance:
                logger.warning(f"C2 instance '{name}' not found.")
                return False
            instance.stop()
            del self.instances[name]
            logger.info(f"C2 instance '{name}' stopped and removed.")
            return True

    def restart_instance(self, name: str) -> bool:
        with self.lock:
            instance = self.instances.get(name)
            if not instance:
                logger.warning(f"C2 instance '{name}' not found.")
                return False
            instance.stop()
            instance.start()
            logger.info(f"C2 instance '{name}' restarted.")
            return True

    def list_instances(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [inst.status() for inst in self.instances.values()]

    def perform_health_checks(self):
        with self.lock:
            for name, instance in self.instances.items():
                result = self.health_checker.check(instance.handler)
                logger.debug(f"Health check for {name}: {result}")
                instance.heartbeat = result.get("last_seen", None)

    def broadcast_command(self, command: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        responses = {}
        with self.lock:
            for name, instance in self.instances.items():
                if not instance.active:
                    continue
                try:
                    response = instance.handler.send_command(command, payload)
                    responses[name] = {"status": "ok", "response": response}
                except Exception as e:
                    responses[name] = {"status": "error", "error": str(e)}
        return responses
