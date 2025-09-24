# genius-core/code-context/plugins/vscode_plugin.py

import asyncio
import json
import websockets
from typing import Dict, Optional
from genius_core.code_context.indexer.index_engine import IndexEngine
from genius_core.code_context.search.semantic_search import SemanticSearch
from genius_core.code_context.agents.context_expander import ContextExpander
from genius_core.code_context.sync.file_change_watcher import FileChangeWatcher

class VSCodePlugin:
    """
    Real-time bidirectional plugin between VSCode extension and TeslaAI Genius Core.
    Handles indexing, semantic retrieval, code context injection and feedback loop.
    """

    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.index_engine = IndexEngine()
        self.search_engine = SemanticSearch()
        self.expander = ContextExpander()
        self.file_watcher = FileChangeWatcher()

    async def _handler(self, websocket, path):
        async for message in websocket:
            try:
                request = json.loads(message)
                action = request.get("action")

                if action == "index":
                    filepath = request["filepath"]
                    self.index_engine.index_file(filepath)
                    await websocket.send(json.dumps({"status": "indexed", "file": filepath}))

                elif action == "search":
                    query = request["query"]
                    results = self.search_engine.search(query)
                    await websocket.send(json.dumps({"status": "ok", "results": results}))

                elif action == "context_expand":
                    symbol = request["symbol"]
                    ctx = self.expander.expand(symbol)
                    await websocket.send(json.dumps({"status": "ok", "context": ctx}))

                elif action == "watch":
                    filepath = request["filepath"]
                    self.file_watcher.watch(filepath)
                    await websocket.send(json.dumps({"status": "watching", "file": filepath}))

                else:
                    await websocket.send(json.dumps({"error": "unknown action"}))

            except Exception as e:
                await websocket.send(json.dumps({"error": str(e)}))

    def run(self):
        print(f"[VSCodePlugin] Listening on ws://{self.host}:{self.port}")
        start_server = websockets.serve(self._handler, self.host, self.port)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()
