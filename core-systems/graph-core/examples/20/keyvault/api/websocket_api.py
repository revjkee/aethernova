# keyvault/api/websocket_api.py

import json
import logging
from typing import Dict, Any

from fastapi import WebSocket, WebSocketDisconnect, APIRouter
from fastapi.websockets import WebSocketState
from starlette.websockets import WebSocketCloseReason
from keyvault.rbac.rbac_evaluator import extract_actor_from_token
from keyvault.access.access_validator import AccessValidator
from keyvault.audit.audit_logger import log_access_event
from keyvault.audit.anomaly_detector import AnomalyDetector
from keyvault.core.secret_manager import retrieve_secret
from keyvault.utils.context_utils import get_current_context_hash
from keyvault.api.websocket_registry import WebSocketRegistry

router = APIRouter()
logger = logging.getLogger("websocket_api")
validator = AccessValidator()
detector = AnomalyDetector()
registry = WebSocketRegistry()

class WebSocketContext:
    def __init__(self, actor_id: str, context: Dict[str, Any]):
        self.actor_id = actor_id
        self.context = context


@router.websocket("/ws/keyvault")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    try:
        # === 1. Инициализация клиента ===
        init_data = await ws.receive_text()
        init_payload = json.loads(init_data)

        token = init_payload.get("token")
        resource = init_payload.get("resource")
        if not token or not resource:
            await ws.close(code=1008)
            return

        actor_id = extract_actor_from_token(token)
        context = {
            "context_hash": get_current_context_hash(actor_id),
            "ip_address": ws.client.host,
            "device_fingerprint": init_payload.get("device_fingerprint"),
            "browser_fingerprint": init_payload.get("browser_fingerprint"),
            "client_version": init_payload.get("client_version"),
            "ws_origin": ws.headers.get("origin")
        }

        ws_context = WebSocketContext(actor_id, context)

        if not validator.validate_access(actor_id, resource, "realtime_listen", context):
            log_access_event(actor_id, resource, "realtime_listen", False, reason="unauthorized", metadata=context)
            await ws.send_json({"error": "Access denied"})
            await ws.close(code=1008)
            return

        log_access_event(actor_id, resource, "realtime_listen", True, metadata=context)
        registry.register(resource, ws)

        await ws.send_json({"status": "subscribed", "resource": resource})

        # === 2. Прослушка/Обработка команд ===
        while True:
            if ws.application_state != WebSocketState.CONNECTED:
                break

            message = await ws.receive_text()
            payload = json.loads(message)
            command = payload.get("command")

            if command == "get_secret":
                if not validator.validate_access(actor_id, resource, "get_secret", context):
                    await ws.send_json({"error": "Access denied"})
                    continue

                event = {
                    "actor_id": actor_id,
                    "resource_id": resource,
                    "action": "get_secret",
                    "timestamp": payload.get("ts", "")
                }

                if detector.analyze_event(event):
                    await ws.send_json({"error": "Anomalous request blocked"})
                    continue

                secret_data = retrieve_secret(resource)
                if not secret_data:
                    await ws.send_json({"error": "Secret not found"})
                    continue

                await ws.send_json({
                    "type": "secret_data",
                    "key": resource,
                    "value": secret_data["value"],
                    "metadata": secret_data.get("metadata", {})
                })

            elif command == "ping":
                await ws.send_json({"type": "pong"})

            else:
                await ws.send_json({"error": "Unknown command"})

    except WebSocketDisconnect:
        logger.info(f"Client disconnected: {ws.client.host}")
    except Exception as e:
        logger.exception(f"WebSocket error: {e}")
    finally:
        registry.unregister(resource, ws)
        await ws.close(code=WebSocketCloseReason.NORMAL_CLOSURE)
