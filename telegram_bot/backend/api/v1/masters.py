from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.core.db import get_session
from backend.models.master import Master
from backend.schemas.master import MasterCreate, MasterOut, MasterUpdate

router = APIRouter(prefix="/masters", tags=["masters"])

# Допустимые имена мастеров
ALLOWED_MASTERS = {"Алиса", "Алексей", "Полина", "Настя", "Дарья"}


@router.get("/", response_model=List[MasterOut])
async def list_masters(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Master))
    masters = result.scalars().all()
    return masters


@router.get("/{master_id}", response_model=MasterOut)
async def get_master(master_id: int, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Master).where(Master.id == master_id))
    master = result.scalar_one_or_none()
    if not master:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Master not found")
    return master


@router.post("/", response_model=MasterOut, status_code=status.HTTP_201_CREATED)
async def create_master(master_in: MasterCreate, session: AsyncSession = Depends(get_session)):
    if master_in.name not in ALLOWED_MASTERS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Имя мастера должно быть одним из: {', '.join(ALLOWED_MASTERS)}")
    master = Master(**master_in.dict())
    session.add(master)
    await session.commit()
    await session.refresh(master)
    return master


@router.put("/{master_id}", response_model=MasterOut)
async def update_master(master_id: int, master_update: MasterUpdate, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Master).where(Master.id == master_id))
    master = result.scalar_one_or_none()
    if not master:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Master not found")

    update_data = master_update.dict(exclude_unset=True)
    if "name" in update_data and update_data["name"] not in ALLOWED_MASTERS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Имя мастера должно быть одним из: {', '.join(ALLOWED_MASTERS)}")

    for key, value in update_data.items():
        setattr(master, key, value)

    await session.commit()
    await session.refresh(master)
    return master


@router.delete("/{master_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_master(master_id: int, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Master).where(Master.id == master_id))
    master = result.scalar_one_or_none()
    if not master:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Master not found")

    await session.delete(master)
    await session.commit()
    return None
