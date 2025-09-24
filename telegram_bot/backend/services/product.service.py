from backend.models.product import Product
from backend.schemas.product import ProductCreate
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

async def create_product(data: ProductCreate, session: AsyncSession):
    obj = Product(**data.dict())
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return obj

async def get_product_by_id(product_id: int, session: AsyncSession):
    result = await session.execute(select(Product).where(Product.id == product_id))
    return result.scalar_one_or_none()
