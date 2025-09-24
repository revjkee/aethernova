# backend/schemas/booking.py
from typing import Optional
from datetime import date
from pydantic import BaseModel, Field, validator

VALID_TIME_SLOTS = {"08:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00"}

class BookingBase(BaseModel):
    master_id: int = Field(..., description="ID мастера для записи")
    date: date = Field(..., description="Дата записи")
    time_slot: str = Field(..., description="Временной слот записи")

    @validator("time_slot")
    def validate_time_slot(cls, v):
        if v not in VALID_TIME_SLOTS:
            raise ValueError(f"Invalid time slot. Allowed values: {', '.join(sorted(VALID_TIME_SLOTS))}")
        return v


class BookingCreate(BookingBase):
    pass


class BookingUpdate(BaseModel):
    master_id: Optional[int] = Field(None, description="ID мастера")
    date: Optional[date] = Field(None, description="Дата записи")
    time_slot: Optional[str] = Field(None, description="Временной слот")

    @validator("time_slot")
    def validate_time_slot(cls, v):
        if v is not None and v not in VALID_TIME_SLOTS:
            raise ValueError(f"Invalid time slot. Allowed values: {', '.join(sorted(VALID_TIME_SLOTS))}")
        return v


class BookingOut(BookingBase):
    id: int

    class Config:
        orm_mode = True
