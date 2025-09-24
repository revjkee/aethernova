from typing import List, Optional
from datetime import time

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, validator
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.db import get_session
from backend.services.timeslot_service import TimeslotService

router = APIRouter(prefix="/timeslots", tags=["timeslots"])

VALID_TIME_SLOTS = {
    time(8, 0),
    time(10, 0),
    time(12, 0),
    time(14, 0),
    time(16, 0),
    time(18, 0),
    time(20, 0),
}

class TimeslotCreate(BaseModel):
    start_time: time = Field(..., description="Время начала слота")
    end_time: time = Field(..., description="Время конца слота")

    @validator('start_time')
    def start_time_must_be_valid(cls, v):
        if v not in VALID_TIME_SLOTS:
            raise ValueError("start_time должен быть одним из фиксированных слотов: "
                             + ", ".join(t.strftime("%H:%M") for t in sorted(VALID_TIME_SLOTS)))
        return v

    @validator('end_time')
    def end_time_must_be_valid(cls, v):
        if v not in VALID_TIME_SLOTS:
            raise ValueError("end_time должен быть одним из фиксированных слотов: "
                             + ", ".join(t.strftime("%H:%M") for t in sorted(VALID_TIME_SLOTS)))
        return v

class TimeslotUpdate(BaseModel):
    start_time: Optional[time] = Field(None, description="Новое время начала")

    end_time: Optional[time] = Field(None, description="Новое время конца")

    @validator('start_time')
    def start_time_must_be_valid(cls, v):
        if v is not None and v not in VALID_TIME_SLOTS:
            raise ValueError("start_time должен быть одним из фиксированных слотов: "
                             + ", ".join(t.strftime("%H:%M") for t in sorted(VALID_TIME_SLOTS)))
        return v

    @validator('end_time')
    def end_time_must_be_valid(cls, v):
        if v is not None and v not in VALID_TIME_SLOTS:
            raise ValueError("end_time должен быть одним из фиксированных слотов: "
                             + ", ".join(t.strftime("%H:%M") for t in sorted(VALID_TIME_SLOTS)))
        return v

class TimeslotOut(BaseModel):
    id: int
    start_time: time
    end_time: time

    class Config:
        orm_mode = True


@router.get("/", response_model=List[TimeslotOut])
async def list_timeslots(
    session: AsyncSession = Depends(get_session),
) -> List[TimeslotOut]:
    service = TimeslotService(session)
    return await service.list_timeslots()


@router.get("/{timeslot_id}", response_model=TimeslotOut)
async def get_timeslot(
    timeslot_id: int,
    session: AsyncSession = Depends(get_session),
) -> TimeslotOut:
    service = TimeslotService(session)
    slot = await service.get_timeslot(timeslot_id)
    if not slot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Timeslot not found")
    return slot


@router.post("/", response_model=TimeslotOut, status_code=status.HTTP_201_CREATED)
async def create_timeslot(
    data: TimeslotCreate,
    session: AsyncSession = Depends(get_session),
) -> TimeslotOut:
    service = TimeslotService(session)
    try:
        slot = await service.create_timeslot(
            start_time=data.start_time,
            end_time=data.end_time,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return slot


@router.put("/{timeslot_id}", response_model=TimeslotOut)
async def update_timeslot(
    timeslot_id: int,
    data: TimeslotUpdate,
    session: AsyncSession = Depends(get_session),
) -> TimeslotOut:
    service = TimeslotService(session)
    slot = await service.update_timeslot(
        timeslot_id=timeslot_id,
        start_time=data.start_time,
        end_time=data.end_time,
    )
    if not slot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Timeslot not found")
    return slot


@router.delete("/{timeslot_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_timeslot(
    timeslot_id: int,
    session: AsyncSession = Depends(get_session),
) -> None:
    service = TimeslotService(session)
    success = await service.delete_timeslot(timeslot_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Timeslot not found")
    return None
