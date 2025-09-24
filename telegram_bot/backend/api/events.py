from typing import Any, Dict
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.core.message_queue import message_publisher  # абстракция для очереди сообщений

router = APIRouter(prefix="/events", tags=["events"])


class Event(BaseModel):
    type: str = Field(..., description="Тип события для публикации")
    payload: Dict[str, Any] = Field(..., description="Полезные данные события")


@router.post("/", status_code=status.HTTP_202_ACCEPTED)
async def publish_event(event: Event):
    # Отправляет событие в очередь сообщений для последующей обработки воркером
    try:
        await message_publisher.publish(event.type, event.payload)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Publish error: {e}")
    return {"status": "accepted"}
