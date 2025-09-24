from backend.models.review import Review
from backend.schemas.review import ReviewCreate
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

async def create_review(data: ReviewCreate, session: AsyncSession):
    obj = Review(**data.dict())
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return obj

async def get_reviews_for_product(product_id: int, session: AsyncSession):
    result = await session.execute(select(Review).where(Review.product_id == product_id))
    return result.scalars().all()
