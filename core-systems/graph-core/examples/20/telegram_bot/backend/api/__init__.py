# в backend/api/v1/__init__.py
from fastapi import APIRouter
from .products import router as products_router
from .reviews import router as reviews_router

api_router = APIRouter()
api_router.include_router(products_router, prefix="/products", tags=["products"])
api_router.include_router(reviews_router, prefix="/reviews", tags=["reviews"])
