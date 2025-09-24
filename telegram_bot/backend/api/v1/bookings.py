from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.core.db import get_session
from backend.models.booking import Booking
from backend.schemas.booking import BookingCreate, BookingOut, BookingUpdate

router = APIRouter(prefix="/bookings", tags=["bookings"])

@router.get("/", response_model=List[BookingOut])
async def list_bookings(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Booking).order_by(Booking.date.desc(), Booking.time_slot))
    bookings = result.scalars().all()
    return bookings


@router.get("/{booking_id}", response_model=BookingOut)
async def get_booking(booking_id: int, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Booking).where(Booking.id == booking_id))
    booking = result.scalar_one_or_none()
    if not booking:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")
    return booking


@router.post("/", response_model=BookingOut, status_code=status.HTTP_201_CREATED)
async def create_booking(booking_in: BookingCreate, session: AsyncSession = Depends(get_session)):
    booking = Booking(**booking_in.dict())
    session.add(booking)
    await session.commit()
    await session.refresh(booking)
    return booking


@router.put("/{booking_id}", response_model=BookingOut)
async def update_booking(booking_id: int, booking_update: BookingUpdate, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Booking).where(Booking.id == booking_id))
    booking = result.scalar_one_or_none()
    if not booking:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

    update_data = booking_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(booking, key, value)

    await session.commit()
    await session.refresh(booking)
    return booking


@router.delete("/{booking_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_booking(booking_id: int, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Booking).where(Booking.id == booking_id))
    booking = result.scalar_one_or_none()
    if not booking:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

    await session.delete(booking)
    await session.commit()
    return None
