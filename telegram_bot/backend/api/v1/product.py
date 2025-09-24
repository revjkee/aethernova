from fastapi import APIRouter, Depends
from backend.schemas.product import ProductCreate, ProductOut
from backend.services.product_service import create_product, get_product_by_id
from backend.core.db import get_async_session

router = APIRouter()

@router.post("/", response_model=ProductOut)
async def add_product(product: ProductCreate, session = Depends(get_async_session)):
    return await create_product(product, session)

@router.get("/{product_id}", response_model=ProductOut)
async def get_product(product_id: int, session = Depends(get_async_session)):
    return await get_product_by_id(product_id, session)
