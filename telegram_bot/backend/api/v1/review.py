from fastapi import APIRouter, Depends
from backend.schemas.review import ReviewCreate, ReviewOut
from backend.services.review_service import create_review, get_reviews_for_product
from backend.core.db import get_async_session

router = APIRouter()

@router.post("/", response_model=ReviewOut)
async def add_review(review: ReviewCreate, session = Depends(get_async_session)):
    return await create_review(review, session)

@router.get("/product/{product_id}", response_model=list[ReviewOut])
async def get_reviews(product_id: int, session = Depends(get_async_session)):
    return await get_reviews_for_product(product_id, session)
