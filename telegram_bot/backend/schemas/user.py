# backend/schemas/user.py
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    username: str = Field(..., description="Логин пользователя")
    email: Optional[EmailStr] = Field(None, description="Email пользователя")


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="Пароль пользователя")


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, description="Новое имя пользователя")
    email: Optional[EmailStr] = Field(None, description="Новый email")
    password: Optional[str] = Field(None, min_length=8, description="Новый пароль")


class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[EmailStr]
    is_active: bool
    is_admin: bool
    created_at: datetime

    class Config:
        orm_mode = True
