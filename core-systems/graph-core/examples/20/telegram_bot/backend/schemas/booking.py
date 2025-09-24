# backend/schemas/booking.py
from typing import Optional
from datetime import date, time
from pydantic import BaseModel, Field


class BookingBase(BaseModel):
    master_id: int = Field(..., description="ID мастера")
    date: date = Field(..., description="Дата записи")
    time_slot: time = Field(..., description="Временной слот записи")


class BookingCreate(BookingBase):
    pass  # Для создания пока достаточно базовых полей


class BookingUpdate(BaseModel):
    master_id: Optional[int] = Field(None, description="ID мастера")
    date: Optional[date] = Field(None, description="Дата записи")
    time_slot: Optional[time] = Field(None, description="Временной слот записи")


class BookingOut(BookingBase):
    id: int

    class Config:
        orm_mode = True
