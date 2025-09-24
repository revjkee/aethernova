from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Time, String, Boolean
from backend.models.base import Base
from typing import List, Optional, TYPE_CHECKING
from datetime import time
from pydantic import BaseModel

if TYPE_CHECKING:
    from backend.models.booking import Booking  # импорт только для типизации, чтобы избежать циклов

class Timeslot(Base):
    __tablename__ = "timeslots"

    start_time: Mapped[time] = mapped_column(Time, nullable=False)
    end_time: Mapped[time] = mapped_column(Time, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)

    bookings: Mapped[List["Booking"]] = relationship(back_populates="timeslot")

    def __repr__(self):
        return f"<Timeslot({self.start_time.strftime('%H:%M')} - {self.end_time.strftime('%H:%M')}, active={self.is_active})>"

class TimeslotData(BaseModel):
    id: int
    start_time: time
    end_time: time
    description: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True  # для Pydantic v2 (раньше orm_mode=True)
