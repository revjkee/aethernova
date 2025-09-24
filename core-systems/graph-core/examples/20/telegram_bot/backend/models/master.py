from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Boolean
from backend.models.base import Base
from typing import List
from pydantic import BaseModel

class MasterData(BaseModel):
    id: int
    name: str
    # остальные поля по модели Master

    class Config:
        from_attributes = True  # для Pydantic v2
        
class Master(Base):
    __tablename__ = "masters"

    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    email: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)

    # Автоматические поля created_at, updated_at в Base

    bookings: Mapped[List["Booking"]] = relationship(back_populates="master")

    def __repr__(self):
        return f"<Master(name={self.name!r}, is_active={self.is_active})>"
