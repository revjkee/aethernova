from typing import Optional, Literal
from pydantic import BaseModel, Field

# Список допустимых имён мастеров
AllowedMasterName = Literal["Алиса", "Алексей", "Полина", "Настя", "Дарья"]

class MasterBase(BaseModel):
    name: AllowedMasterName = Field(..., description="Имя мастера из разрешенного списка")
    phone: Optional[str] = Field(None, description="Телефон мастера")
    email: Optional[str] = Field(None, description="Email мастера")
    is_active: Optional[bool] = Field(True, description="Активен ли мастер для записи")

class MasterCreate(MasterBase):
    pass

class MasterUpdate(BaseModel):
    name: Optional[AllowedMasterName] = Field(None, description="Имя мастера из разрешенного списка")
    phone: Optional[str] = Field(None, description="Телефон мастера")
    email: Optional[str] = Field(None, description="Email мастера")
    is_active: Optional[bool] = Field(None, description="Активен ли мастер для записи")

class MasterOut(MasterBase):
    id: int

    class Config:
        orm_mode = True
