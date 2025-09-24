from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.models.base import Base
from datetime import datetime
from pydantic import BaseModel

class BookingData(BaseModel):
    id: int
    user_id: int
    master_id: int
    timeslot_id: int
    date: datetime
    confirmed: bool

    class Config:
        orm_mode = True
        
class Booking(Base):
    __tablename__ = "bookings"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    master_id: Mapped[int] = mapped_column(ForeignKey("masters.id", ondelete="CASCADE"), nullable=False)
    timeslot_id: Mapped[int] = mapped_column(ForeignKey("timeslots.id", ondelete="CASCADE"), nullable=False)

    date: Mapped[datetime] = mapped_column(nullable=False)
    confirmed: Mapped[bool] = mapped_column(default=False)

    # relationships
    user: Mapped["User"] = relationship(back_populates="bookings")
    master: Mapped["Master"] = relationship(back_populates="bookings")
    timeslot: Mapped["Timeslot"] = relationship(back_populates="bookings")

    def __repr__(self):
        return (f"<Booking(user_id={self.user_id}, master_id={self.master_id}, "
                f"timeslot_id={self.timeslot_id}, date={self.date.strftime('%Y-%m-%d')}, confirmed={self.confirmed})>")
