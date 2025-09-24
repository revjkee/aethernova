from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.db import get_session
from backend.services.user_service import UserService
from backend.api.v1.users_schemas import UserCreate, UserUpdate, UserOut

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/", response_model=List[UserOut])
async def list_users(session: AsyncSession = Depends(get_session)) -> List[UserOut]:
    service = UserService(session)
    return await service.list_users()


@router.get("/{user_id}", response_model=UserOut)
async def get_user(user_id: int, session: AsyncSession = Depends(get_session)) -> UserOut:
    service = UserService(session)
    user = await service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.post("/", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(data: UserCreate, session: AsyncSession = Depends(get_session)) -> UserOut:
    service = UserService(session)
    try:
        user = await service.create_user(
            username=data.username,
            email=data.email,
            password=data.password
        )
    except Exception as e:
        # Можно уточнить типы ошибок в сервисе и обработать по ним
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return user


@router.put("/{user_id}", response_model=UserOut)
async def update_user(user_id: int, data: UserUpdate, session: AsyncSession = Depends(get_session)) -> UserOut:
    service = UserService(session)
    user = await service.update_user(
        user_id=user_id,
        username=data.username,
        email=data.email,
        password=data.password,
        is_active=data.is_active,
        is_admin=data.is_admin,
    )
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: int, session: AsyncSession = Depends(get_session)) -> None:
    service = UserService(session)
    success = await service.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return None
