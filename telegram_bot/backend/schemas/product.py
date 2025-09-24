from pydantic import BaseModel
from typing import Optional

class ProductCreate(BaseModel):
    title: str
    description: str
    video_url: str
    price: float
    owner_id: int

class ProductOut(ProductCreate):
    id: int
    is_active: bool
