from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
import httpx
import asyncio
import logging
import os
import uuid
from datetime import datetime
import json
import aiofiles

app = FastAPI()

# === Конфигурация ===
AI_AGENT_URL = os.getenv("AI_AGENT_URL", "http://ai-router:8080/intents/alerts")
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENCY", 20))
DEADLETTER_DIR = os.getenv("DEADLETTER_DIR", "/var/log/alert-router-deadletter")
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

# === Логгирование ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("alert-router")

# === Приём Alertmanager webhook ===
@app.post("/api/v1/incident")
async def receive_alert(request: Request):
    try:
        payload = await request.json()
        alerts = payload.get("alerts", [])
    except Exception as e:
        logger.error(f"Invalid JSON payload: {e}")
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "Invalid JSON"})

    if not alerts:
        return {"status": "no alerts"}

    tasks = [process_alert(alert) for alert in alerts]
    await asyncio.gather(*tasks)
    return {"status": "ok", "processed": len(alerts)}


# === Обработка одного алерта ===
async def process_alert(alert: dict):
    summary = alert.get("annotations", {}).get("summary", "No summary")
    description = alert.get("annotations", {}).get("description", "No description")
    severity = alert.get("labels", {}).get("severity", "unknown")
    alertname = alert.get("labels", {}).get("alertname", "generic")
    team = alert.get("labels", {}).get("team", "unknown")
    fingerprint = alert.get("fingerprint", str(uuid.uuid4()))
    source = alert.get("generatorURL", "unknown")
    timestamp = alert.get("startsAt", datetime.utcnow().isoformat())

    enriched = {
        "intent": "alert_received",
        "incident_id": fingerprint,
        "source": source,
        "data": {
            "summary": summary,
            "description": description,
            "severity": severity,
            "alertname": alertname,
            "team": team,
            "timestamp": timestamp
        }
    }

    async with semaphore:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(AI_AGENT_URL, json=enriched)
                response.raise_for_status()
                logger.info(f"Alert routed: {alertname} ({severity}) -> {team}")
        except httpx.RequestError as e:
            logger.warning(f"HTTP error while routing alert: {e}")
            await write_deadletter(enriched)
        except httpx.HTTPStatusError as e:
            logger.error(f"AI-agent returned HTTP {e.response.status_code}")
            await write_deadletter(enriched)


# === Deadletter fallback ===
async def write_deadletter(alert: dict):
    try:
        os.makedirs(DEADLETTER_DIR, exist_ok=True)
        filename = f"{DEADLETTER_DIR}/{uuid.uuid4()}.json"
        async with aiofiles.open(filename, mode='w') as f:
            await f.write(json.dumps(alert, indent=2))
        logger.info(f"Deadletter saved: {filename}")
    except Exception as e:
        logger.critical(f"Failed to write deadletter: {e}")
