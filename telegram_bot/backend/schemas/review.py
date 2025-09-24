from pydantic import BaseModel
from typing import Optional

class ReviewCreate(BaseModel):
    product_id: int
    user_id: int
    text: str
    stars: int

class ReviewOut(ReviewCreate):
    id: int
