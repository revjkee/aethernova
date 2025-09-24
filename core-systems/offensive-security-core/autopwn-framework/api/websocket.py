# autopwn-framework/api/websocket.py

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from typing import List

app = FastAPI(title="Autopwn Framework WebSocket API", version="1.0")

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws/scan")
async def websocket_endpoint(websocket: WebSocket):
    """
    Вебсокет для взаимодействия с клиентом в реальном времени.
    Клиент может отправлять команды запуска сканирования и получать результаты по мере выполнения.
    """
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Здесь должна быть логика обработки команды, например:
            # parse data, запустить сканирование, отправлять прогресс
            # Для примера просто возвращаем подтверждение
            await manager.send_personal_message(f"Команда получена: {data}", websocket)

            # Имитация отправки прогресса или результатов
            await manager.send_personal_message("Сканирование запущено...", websocket)
            await manager.send_personal_message("Сканирование завершено. Найдено 2 уязвимости.", websocket)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
