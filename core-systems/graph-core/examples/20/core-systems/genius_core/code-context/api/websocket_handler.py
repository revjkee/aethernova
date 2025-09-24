# genius-core/code-context/api/websocket_handler.py

import asyncio
import logging
import json
from fastapi import WebSocket, WebSocketDisconnect, Depends
from fastapi.routing import APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, List
from uuid import uuid4

from genius_core.code_context.sync.file_change_watcher import FileChangeWatcher
from genius_core.code_context.search.semantic_search import SemanticSearch

router = APIRouter()
logger = logging.getLogger("websocket_handler")
logging.basicConfig(level=logging.INFO)

# Security
auth_scheme = HTTPBearer()
VALID_TOKENS = {"teslaai-super-token"}

async def verify_token(websocket: WebSocket):
    token = websocket.headers.get("Authorization")
    if not token or token.replace("Bearer ", "") not in VALID_TOKENS:
        await websocket.close(code=4403)
        return False
    return True

# Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket) -> str:
        await websocket.accept()
        client_id = str(uuid4())
        self.active_connections[client_id] = websocket
        logger.info(f"Client {client_id} connected.")
        return client_id

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"Client {client_id} disconnected.")

    async def send_json(self, client_id: str, data: dict):
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_json(data)

    async def broadcast(self, data: dict):
        for ws in self.active_connections.values():
            await ws.send_json(data)

manager = ConnectionManager()
watcher = FileChangeWatcher()
search_engine = SemanticSearch()

# Message router
@router.websocket("/ws/code-context")
async def websocket_endpoint(websocket: WebSocket):
    if not await verify_token(websocket):
        return

    client_id = await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()

            # Protocol: { "action": "...", "payload": { ... } }
            action = data.get("action")
            payload = data.get("payload", {})

            if action == "watch":
                # Start watching a file/dir
                path = payload.get("path")
                if path:
                    await watcher.register(path, lambda ev: asyncio.create_task(manager.send_json(client_id, {
                        "event": "file_change",
                        "details": ev
                    })))
                    await manager.send_json(client_id, {"status": f"watching {path}"})

            elif action == "search":
                query = payload.get("query")
                if query:
                    results = search_engine.search(query, top_k=5)
                    await manager.send_json(client_id, {"event": "search_results", "results": results})

            else:
                await manager.send_json(client_id, {"error": "Unknown action"})

    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.exception("WebSocket error:")
        await websocket.close()

