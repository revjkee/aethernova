# autopwn-framework/api/rest.py

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Autopwn Framework REST API", version="1.0")

# Пример модели запроса
class ScanRequest(BaseModel):
    target: str
    profile: Optional[str] = "fast_scan"
    timeout: Optional[int] = 60

# Пример модели ответа
class ScanResult(BaseModel):
    target: str
    status: str
    vulnerabilities: list

@app.post("/scan", response_model=ScanResult)
async def start_scan(request: ScanRequest):
    """
    Запуск сканирования по профилю.
    Входные параметры:
    - target: цель для сканирования (IP, домен)
    - profile: профиль сканера (fast_scan, full_scan и т.д.)
    - timeout: максимальное время сканирования (секунды)
    """
    # Здесь должна быть логика запуска сканера (псевдокод)
    # result = scan_engine.run(target=request.target, profile=request.profile, timeout=request.timeout)
    # Для примера возврат фиктивного результата

    if not request.target:
        raise HTTPException(status_code=400, detail="Target is required")

    dummy_result = ScanResult(
        target=request.target,
        status="completed",
        vulnerabilities=[
            {"name": "CVE-2021-1234", "severity": "high"},
            {"name": "CVE-2020-5678", "severity": "medium"},
        ]
    )
    return dummy_result

@app.get("/health")
async def health_check():
    """
    Проверка состояния API
    """
    return {"status": "ok"}

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Глобальный обработчик ошибок API
    """
    return JSONResponse(
        status_code=500,
        content={"message": "Internal server error", "details": str(exc)},
    )
