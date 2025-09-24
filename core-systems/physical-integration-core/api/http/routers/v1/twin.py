# physical-integration-core/api/http/routers/v1/twin.py
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, validator

# ---------------------------
# Pydantic models (stable API)
# ---------------------------

class CPUInfo(BaseModel):
    arch: str = Field(..., example="arm64")
    cores: int = Field(..., ge=1, le=256)
    model_name: Optional[str] = Field(None, example="Cortex-A76")
    max_freq_mhz: Optional[int] = Field(None, ge=1, le=100000)

class MemoryInfo(BaseModel):
    ram_total_bytes: int = Field(..., ge=0)
    nvram_bytes: Optional[int] = Field(None, ge=0)

class StorageInfo(BaseModel):
    total_bytes: int = Field(..., ge=0)
    fs_type: Optional[str] = Field(None, example="ext4")
    dual_rootfs: Optional[bool] = False

class OSInfo(BaseModel):
    type: str = Field(..., example="linux")
    distro: Optional[str] = Field(None, example="AL2023")
    version: Optional[str] = Field(None, example="6.1.38")
    kernel: Optional[str] = None

class DeviceSpec(BaseModel):
    model: str = Field(..., example="PI_CORE_EDGE")
    hw_revision: Optional[str] = Field(None, example="B3")
    sku: Optional[str] = None
    cpu: Optional[CPUInfo] = None
    memory: Optional[MemoryInfo] = None
    storage: Optional[StorageInfo] = None
    os: Optional[OSInfo] = None
    capabilities: List[str] = Field(default_factory=list)

class HealthSignal(BaseModel):
    name: str
    value: float
    unit: Optional[str] = None
    message: Optional[str] = None
    time: Optional[datetime] = None

class Health(BaseModel):
    state: str = Field(..., regex="^(OK|WARN|ERROR|CRIT|UNSPECIFIED)$")
    signals: List[HealthSignal] = Field(default_factory=list)
    summary: Optional[str] = None

class IPAddress(BaseModel):
    address: str
    gateway: Optional[str] = None
    dns: List[str] = Field(default_factory=list)

class NetworkInterface(BaseModel):
    name: str = Field(..., example="eth0")
    type: str = Field(..., regex="^(ETHERNET|WIFI|CELLULAR|OTHER|UNSPECIFIED)$")
    mac: Optional[str] = Field(None, example="AA:BB:CC:DD:EE:FF")
    addresses: List[IPAddress] = Field(default_factory=list)
    rssi_dbm: Optional[int] = None
    ssid: Optional[str] = None
    apn: Optional[str] = None
    connected: bool = False
    last_change_time: Optional[datetime] = None

class PowerStatus(BaseModel):
    source: str = Field(..., regex="^(AC|DC|BATTERY|POE|UNSPECIFIED)$")
    battery_percent: Optional[float] = Field(None, ge=0, le=100)
    on_ac: Optional[bool] = None
    voltage_v: Optional[float] = None
    current_a: Optional[float] = None
    charging: Optional[bool] = None
    last_change_time: Optional[datetime] = None

class OTAStatus(BaseModel):
    state: str = Field(..., regex="^(IDLE|DOWNLOADING|INSTALLING|REBOOTING|ROLLBACK|FAILED|SUCCESS|UNSPECIFIED)$")
    current_version: Optional[str] = None
    target_version: Optional[str] = None
    slot_active: Optional[str] = Field(None, regex="^(A|B)$")
    progress_percent: Optional[int] = Field(None, ge=0, le=100)
    last_change_time: Optional[datetime] = None

class TelemetryCPU(BaseModel):
    load1: Optional[float] = None
    load5: Optional[float] = None
    load15: Optional[float] = None
    usage_percent: Optional[float] = Field(None, ge=0, le=100)

class TelemetryMemory(BaseModel):
    total_bytes: Optional[int] = Field(None, ge=0)
    used_bytes: Optional[int] = Field(None, ge=0)
    free_bytes: Optional[int] = Field(None, ge=0)

class TelemetryDisk(BaseModel):
    total_bytes: Optional[int] = Field(None, ge=0)
    used_bytes: Optional[int] = Field(None, ge=0)
    inode_used_percent: Optional[float] = Field(None, ge=0, le=100)

class TelemetryTemp(BaseModel):
    cpu_celsius: Optional[float] = None
    board_celsius: Optional[float] = None
    ambient_celsius: Optional[float] = None

class TelemetrySummary(BaseModel):
    cpu: Optional[TelemetryCPU] = None
    mem: Optional[TelemetryMemory] = None
    disk: Optional[TelemetryDisk] = None
    temp: Optional[TelemetryTemp] = None

class DeviceStatus(BaseModel):
    state: str = Field(..., regex="^(PROVISIONING|ACTIVE|DEGRADED|MAINTENANCE|OFFLINE|RETIRED|UNSPECIFIED)$")
    health: Optional[Health] = None
    networks: List[NetworkInterface] = Field(default_factory=list)
    power: Optional[PowerStatus] = None
    ota: Optional[OTAStatus] = None
    telemetry: Optional[TelemetrySummary] = None
    update_time: Optional[datetime] = None

class DeviceIdentity(BaseModel):
    device_id: UUID
    display_name: Optional[str] = None
    vendor: Optional[str] = None
    serial_number: Optional[str] = None
    mac_address: Optional[str] = None
    tpm_ek_pub_der: Optional[bytes] = None
    imei: Optional[str] = None
    register_time: Optional[datetime] = None
    last_seen: Optional[datetime] = None

class Twin(BaseModel):
    identity: DeviceIdentity
    spec: Optional[DeviceSpec] = None
    status: Optional[DeviceStatus] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)
    version: int = Field(..., ge=1)
    create_time: datetime
    update_time: datetime

    class Config:
        extra = "forbid"

class TelemetryEnvelope(BaseModel):
    device_id: UUID
    time: Optional[datetime] = None
    metrics: Dict[str, float] = Field(default_factory=dict)
    logs: List[Dict[str, Any]] = Field(default_factory=list)
    events: List[Dict[str, Any]] = Field(default_factory=list)

class CommandIn(BaseModel):
    type: str = Field(..., regex=r"^[A-Z0-9_\.:-]{1,64}$", example="CMD_REBOOT")
    timeout_seconds: Optional[int] = Field(None, ge=1, le=3600)
    params: Dict[str, str] = Field(default_factory=dict)

class Command(BaseModel):
    command_id: UUID
    device_id: UUID
    type: str
    timeout_seconds: Optional[int] = None
    params: Dict[str, str] = Field(default_factory=dict)
    create_time: datetime

class CommandResultIn(BaseModel):
    status: str = Field(..., regex="^(ACCEPTED|RUNNING|SUCCEEDED|FAILED|TIMEOUT|REJECTED)$")
    exit_code: Optional[int] = None
    message: Optional[str] = None

class CommandResult(BaseModel):
    command_id: UUID
    device_id: UUID
    status: str
    exit_code: Optional[int] = None
    message: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

# ---------------------------
# Repository protocol and impl
# ---------------------------

class TwinRepository:
    """Thread-safe in-memory repository with optimistic locking and idempotency map."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._twins: Dict[UUID, Twin] = {}
        self._commands: Dict[UUID, List[Command]] = {}
        self._cmd_results: Dict[UUID, Dict[UUID, CommandResult]] = {}
        self._idempotency: Dict[str, UUID] = {}

    async def get(self, device_id: UUID) -> Optional[Twin]:
        async with self._lock:
            return self._twins.get(device_id)

    async def list(
        self,
        *,
        page_size: int,
        page_token: Optional[str],
        state: Optional[str],
        model: Optional[str],
        labels: Dict[str, str],
    ) -> Tuple[List[Twin], Optional[str]]:
        async with self._lock:
            items = list(self._twins.values())
            if state:
                items = [t for t in items if t.status and t.status.state == state]
            if model:
                items = [t for t in items if t.spec and t.spec.model == model]
            for k, v in labels.items():
                items = [t for t in items if t.labels.get(k) == v]

            start = 0
            if page_token:
                try:
                    start = int(base64.urlsafe_b64decode(page_token.encode()).decode())
                except Exception:
                    start = 0
            end = min(start + page_size, len(items))
            next_token = base64.urlsafe_b64encode(str(end).encode()).decode() if end < len(items) else None
            return items[start:end], next_token

    async def upsert(self, twin: Twin, *, if_version: Optional[int]) -> Twin:
        async with self._lock:
            current = self._twins.get(twin.identity.device_id)
            if current:
                if if_version is not None and if_version != current.version:
                    raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="Version mismatch")
                twin.version = current.version + 1
                twin.create_time = current.create_time
            else:
                twin.version = 1
                twin.create_time = twin.create_time
            twin.update_time = now_utc()
            self._twins[twin.identity.device_id] = twin
            return twin

    async def patch(self, device_id: UUID, patch: Dict[str, Any], *, if_version: Optional[int]) -> Twin:
        async with self._lock:
            current = self._twins.get(device_id)
            if not current:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Twin not found")
            if if_version is not None and if_version != current.version:
                raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="Version mismatch")
            data = json.loads(current.json())
            merged = json_merge_patch(data, patch)
            updated = Twin.parse_obj(merged)
            updated.version = current.version + 1
            updated.update_time = now_utc()
            self._twins[device_id] = updated
            return updated

    async def update_status(self, device_id: UUID, status_obj: DeviceStatus, *, if_version: Optional[int]) -> Twin:
        async with self._lock:
            current = self._twins.get(device_id)
            if not current:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Twin not found")
            if if_version is not None and if_version != current.version:
                raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="Version mismatch")
            status_obj.update_time = now_utc()
            current.status = status_obj
            current.version += 1
            current.update_time = now_utc()
            self._twins[device_id] = current
            return current

    async def accept_telemetry(self, device_id: UUID, env: TelemetryEnvelope) -> None:
        async with self._lock:
            # No persistence for metrics here; placeholder for pipeline handoff
            if device_id not in self._twins:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Twin not found")
            # Update last_seen
            tw = self._twins[device_id]
            if tw.identity.last_seen is None or (env.time and env.time > tw.identity.last_seen):
                tw.identity.last_seen = env.time or now_utc()
                tw.update_time = now_utc()
                tw.version += 1
                self._twins[device_id] = tw

    async def create_command(self, device_id: UUID, cmd: Command, *, idem_key: Optional[str]) -> Command:
        async with self._lock:
            if device_id not in self._twins:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Twin not found")
            if idem_key:
                existing = self._idempotency.get(idem_key)
                if existing:
                    # Return existing command if id matches
                    cmds = self._commands.get(device_id, [])
                    for c in cmds:
                        if c.command_id == existing:
                            return c
            self._commands.setdefault(device_id, []).append(cmd)
            if idem_key:
                self._idempotency[idem_key] = cmd.command_id
            return cmd

    async def list_commands(
        self, device_id: UUID, *, page_size: int, page_token: Optional[str]
    ) -> Tuple[List[Command], Optional[str]]:
        async with self._lock:
            cmds = self._commands.get(device_id, [])
            start = 0
            if page_token:
                try:
                    start = int(base64.urlsafe_b64decode(page_token.encode()).decode())
                except Exception:
                    start = 0
            end = min(start + page_size, len(cmds))
            next_token = base64.urlsafe_b64encode(str(end).encode()).decode() if end < len(cmds) else None
            return cmds[start:end], next_token

    async def submit_result(self, device_id: UUID, command_id: UUID, result: CommandResult) -> CommandResult:
        async with self._lock:
            cmds = self._commands.get(device_id, [])
            if not any(c.command_id == command_id for c in cmds):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Command not found")
            self._cmd_results.setdefault(device_id, {})[command_id] = result
            return result

    async def get_result(self, device_id: UUID, command_id: UUID) -> Optional[CommandResult]:
        async with self._lock:
            return self._cmd_results.get(device_id, {}).get(command_id)

# Global repo instance (can be swapped by DI)
_repo = TwinRepository()

def get_repo() -> TwinRepository:
    return _repo

# ---------------------------
# Utilities
# ---------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def compute_etag(version: int, update_time: datetime) -> str:
    h = hashlib.sha256(f"{version}:{update_time.timestamp()}".encode()).digest()
    return 'W/"%s"' % base64.urlsafe_b64encode(h).decode()

def parse_if_match(if_match: Optional[str]) -> Optional[int]:
    if not if_match:
        return None
    # Accept both ETag and raw version number
    if if_match.isdigit():
        return int(if_match)
    return None

def json_merge_patch(target: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    """RFC 7396 like merge-patch for dicts and lists."""
    result = target.copy()
    for k, v in patch.items():
        if v is None:
            result.pop(k, None)
        elif isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = json_merge_patch(result[k], v)
        else:
            result[k] = v
    return result

# ---------------------------
# Router
# ---------------------------

router = APIRouter(prefix="/api/v1/twin", tags=["twin"])

@router.get("", response_model=List[Twin])
async def list_twins(
    response: Response,
    page_size: int = Query(50, ge=1, le=500),
    page_token: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    model: Optional[str] = Query(None),
    label: List[str] = Query(default_factory=list, description="Фильтр label как key:value"),
    repo: TwinRepository = Depends(get_repo),
):
    labels: Dict[str, str] = {}
    for lv in label:
        if ":" in lv:
            k, v = lv.split(":", 1)
            labels[k] = v
    items, next_token = await repo.list(page_size=page_size, page_token=page_token, state=state, model=model, labels=labels)
    if next_token:
        response.headers["X-Next-Page-Token"] = next_token
    # Для списка не ставим общий ETag; клиенты используют пагинацию и условия на элементы.
    return items

@router.get("/{device_id}", response_model=Twin)
async def get_twin(
    device_id: UUID = Path(...),
    request: Request = None,
    response: Response = None,
    repo: TwinRepository = Depends(get_repo),
    if_none_match: Optional[str] = Header(None, convert_underscores=False),
):
    twin = await repo.get(device_id)
    if not twin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Twin not found")
    etag = compute_etag(twin.version, twin.update_time)
    response.headers["ETag"] = etag
    if if_none_match and if_none_match == etag:
        # Not Modified
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return twin
    return twin

@router.put("/{device_id}", response_model=Twin, status_code=status.HTTP_200_OK)
async def upsert_twin(
    device_id: UUID,
    body: Twin = Body(...),
    response: Response = None,
    repo: TwinRepository = Depends(get_repo),
    if_match: Optional[str] = Header(None, convert_underscores=False),
):
    if body.identity.device_id != device_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="device_id mismatch")
    prev = await repo.get(device_id)
    required_if_match = prev is not None
    cond_version = parse_if_match(if_match)
    if required_if_match and cond_version is None:
        raise HTTPException(status_code=status.HTTP_428_PRECONDITION_REQUIRED, detail="If-Match required for update")
    saved = await repo.upsert(body, if_version=cond_version)
    response.headers["ETag"] = compute_etag(saved.version, saved.update_time)
    return saved

@router.patch("/{device_id}", response_model=Twin)
async def patch_twin(
    device_id: UUID,
    patch: Dict[str, Any] = Body(..., media_type="application/merge-patch+json"),
    response: Response = None,
    repo: TwinRepository = Depends(get_repo),
    if_match: Optional[str] = Header(None, convert_underscores=False),
):
    if parse_if_match(if_match) is None:
        raise HTTPException(status_code=status.HTTP_428_PRECONDITION_REQUIRED, detail="If-Match required")
    updated = await repo.patch(device_id, patch, if_version=parse_if_match(if_match))
    response.headers["ETag"] = compute_etag(updated.version, updated.update_time)
    return updated

@router.put("/{device_id}/status", response_model=Twin)
async def put_status(
    device_id: UUID,
    status_obj: DeviceStatus = Body(...),
    response: Response = None,
    repo: TwinRepository = Depends(get_repo),
    if_match: Optional[str] = Header(None, convert_underscores=False),
):
    if parse_if_match(if_match) is None:
        raise HTTPException(status_code=status.HTTP_428_PRECONDITION_REQUIRED, detail="If-Match required")
    updated = await repo.update_status(device_id, status_obj, if_version=parse_if_match(if_match))
    response.headers["ETag"] = compute_etag(updated.version, updated.update_time)
    return updated

@router.post("/{device_id}/telemetry", status_code=status.HTTP_202_ACCEPTED)
async def post_telemetry(
    device_id: UUID,
    env: TelemetryEnvelope = Body(...),
    repo: TwinRepository = Depends(get_repo),
):
    if env.device_id != device_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="device_id mismatch")
    await repo.accept_telemetry(device_id, env)
    return {"accepted": True}

@router.post("/{device_id}/commands", response_model=Command, status_code=status.HTTP_201_CREATED)
async def create_command(
    device_id: UUID,
    cmd_in: CommandIn = Body(...),
    response: Response = None,
    repo: TwinRepository = Depends(get_repo),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    cmd = Command(
        command_id=uuid4(),
        device_id=device_id,
        type=cmd_in.type,
        timeout_seconds=cmd_in.timeout_seconds,
        params=cmd_in.params,
        create_time=now_utc(),
    )
    saved = await repo.create_command(device_id, cmd, idem_key=idempotency_key)
    response.headers["Location"] = f"/api/v1/twin/{device_id}/commands/{saved.command_id}"
    return saved

@router.get("/{device_id}/commands", response_model=List[Command])
async def list_commands(
    device_id: UUID,
    response: Response,
    page_size: int = Query(50, ge=1, le=500),
    page_token: Optional[str] = Query(None),
    repo: TwinRepository = Depends(get_repo),
):
    items, next_token = await repo.list_commands(device_id, page_size=page_size, page_token=page_token)
    if next_token:
        response.headers["X-Next-Page-Token"] = next_token
    return items

@router.get("/{device_id}/commands/{command_id}", response_model=Command)
async def get_command(
    device_id: UUID,
    command_id: UUID,
    repo: TwinRepository = Depends(get_repo),
):
    items, _ = await repo.list_commands(device_id, page_size=10000, page_token=None)
    for c in items:
        if c.command_id == command_id:
            return c
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Command not found")

@router.post("/{device_id}/commands/{command_id}/result", response_model=CommandResult, status_code=status.HTTP_202_ACCEPTED)
async def post_command_result(
    device_id: UUID,
    command_id: UUID,
    result_in: CommandResultIn,
    repo: TwinRepository = Depends(get_repo),
):
    result = CommandResult(
        command_id=command_id,
        device_id=device_id,
        status=result_in.status,
        exit_code=result_in.exit_code,
        message=result_in.message,
        start_time=now_utc(),
        end_time=now_utc(),
    )
    saved = await repo.submit_result(device_id, command_id, result)
    return saved

@router.get("/{device_id}/commands/{command_id}/result", response_model=CommandResult)
async def get_command_result(
    device_id: UUID,
    command_id: UUID,
    repo: TwinRepository = Depends(get_repo),
):
    res = await repo.get_result(device_id, command_id)
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Result not found")
    return res

# Bootstrap helper for creating a skeleton twin if needed (optional)
@router.post("/{device_id}:ensure", response_model=Twin, status_code=status.HTTP_201_CREATED)
async def ensure_twin(
    device_id: UUID,
    display_name: Optional[str] = Query(None),
    vendor: Optional[str] = Query(None),
    repo: TwinRepository = Depends(get_repo),
):
    existing = await repo.get(device_id)
    if existing:
        return existing
    twin = Twin(
        identity=DeviceIdentity(
            device_id=device_id,
            display_name=display_name,
            vendor=vendor,
            register_time=now_utc(),
            last_seen=None,
        ),
        spec=None,
        status=None,
        labels={},
        annotations={},
        version=1,
        create_time=now_utc(),
        update_time=now_utc(),
    )
    created = await repo.upsert(twin, if_version=None)
    return created
