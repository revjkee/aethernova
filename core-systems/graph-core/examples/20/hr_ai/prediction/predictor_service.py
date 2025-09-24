import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
from typing import List, Dict, Any

from hr_ai.prediction.performance_model import PerformancePredictor
from hr_ai.utils.security.auth import validate_api_key
from hr_ai.utils.security.audit import secure_log
from hr_ai.utils.telemetry.tracer import trace_request
from hr_ai.utils.exception_handler import add_exception_handlers

app = FastAPI(title="HR Performance Predictor", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["Authorization", "Content-Type"],
)

add_exception_handlers(app)

class PredictionRequest(BaseModel):
    api_key: str
    features: List[Dict[str, Any]]

class InterpretationRequest(BaseModel):
    api_key: str
    instance: Dict[str, Any]

model_config = {
    "n_estimators": 200,
    "learning_rate": 0.05,
    "max_depth": 4,
    "val_size": 0.2
}

predictor = PerformancePredictor(config=model_config)

@app.post("/predict")
@trace_request
async def predict(req: PredictionRequest):
    if not validate_api_key(req.api_key):
        raise HTTPException(status_code=401, detail="Unauthorized")

    df = pd.DataFrame(req.features)
    secure_log("Prediction requested", context={"records": len(df)})
    predictions = predictor.predict(df)
    return {"predictions": predictions.tolist()}

@app.post("/interpret")
@trace_request
async def interpret(req: InterpretationRequest):
    if not validate_api_key(req.api_key):
        raise HTTPException(status_code=401, detail="Unauthorized")

    df = pd.DataFrame([req.instance])
    contributions = predictor.interpret(df)
    return {"interpretation": contributions}

@app.on_event("startup")
def startup_event():
    secure_log("Predictor service starting", context={})
    # Опционально: загрузить предобученную модель
    # predictor.load_model("models/performance_model.pkl")

@app.get("/health")
def health_check():
    return {"status": "ok", "version": app.version}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
