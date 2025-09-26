from fastapi import Request
from fastapi.responses import JSONResponse

# Reuse the FastAPI app implemented under src.main
from src.main import app


@app.get("/health", include_in_schema=False)
async def health_compat():
    # call existing health handler if available
    try:
        from src.api import health_check
        return await health_check()
    except Exception:
        return {"status": "ok"}


@app.get("/", include_in_schema=False)
async def root_compat():
    return {"message": "Welcome to TeslaAI Backend"}


@app.get("/api/protected-resource", include_in_schema=False)
async def protected_resource(request: Request):
    auth = request.headers.get("Authorization")
    if not auth:
        return JSONResponse(status_code=401, content={})
    return {"data": "protected"}
