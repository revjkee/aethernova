"""
models.py
Модели данных для хранения информации, полученной OSINT-сканерами.

Определяет структуры для типовых сущностей: пользователей,
форумных сообщений, социальных постов и т.п., с учётом гибкости и масштабируемости.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime

class User(BaseModel):
    user_id: str = Field(..., description="Уникальный идентификатор пользователя")
    username: Optional[str] = Field(None, description="Имя пользователя")
    profile_url: Optional[str] = Field(None, description="URL профиля пользователя")
    extra: Optional[Dict] = Field(default_factory=dict, description="Дополнительные данные")

class ForumPost(BaseModel):
    post_id: str = Field(..., description="Уникальный идентификатор поста")
    user: User = Field(..., description="Автор поста")
    content: str = Field(..., description="Текст сообщения")
    created_at: datetime = Field(..., description="Время создания поста")
    url: Optional[str] = Field(None, description="URL поста")
    metadata: Optional[Dict] = Field(default_factory=dict, description="Дополнительные метаданные")

class SocialMediaPost(BaseModel):
    post_id: str = Field(..., description="Уникальный идентификатор поста в соцсети")
    user: User = Field(..., description="Автор поста")
    content: str = Field(..., description="Текст сообщения")
    created_at: datetime = Field(..., description="Время публикации")
    platform: str = Field(..., description="Платформа (например, Twitter, Facebook)")
    url: Optional[str] = Field(None, description="URL поста")
    metadata: Optional[Dict] = Field(default_factory=dict, description="Дополнительные метаданные")

class ScanResult(BaseModel):
    source: str = Field(..., description="Источник данных (форум, соцсеть и т.п.)")
    items: List[BaseModel] = Field(..., description="Список данных, полученных сканером")
    scanned_at: datetime = Field(default_factory=datetime.utcnow, description="Время сканирования")
    extra: Optional[Dict] = Field(default_factory=dict, description="Дополнительная информация")
