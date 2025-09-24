from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Boolean
from backend.models.base import Base
from passlib.context import CryptContext
from typing import List, Optional


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(100), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(128), nullable=False)
    wallet_address: Mapped[Optional[str]] = mapped_column(String(64))

    is_active: Mapped[bool] = mapped_column(default=True)
    is_admin: Mapped[bool] = mapped_column(default=False)

    bookings: Mapped[List["Booking"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    products: Mapped[List["Product"]] = relationship(back_populates="owner", cascade="all, delete-orphan")

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.hashed_password)

    def set_password(self, password: str) -> None:
        self.hashed_password = pwd_context.hash(password)

    def __repr__(self):
        return f"<User(username={self.username!r}, email={self.email!r}, is_active={self.is_active})>"
