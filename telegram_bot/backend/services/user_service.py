from backend.models.user import User, User_Pydantic, UserIn_Pydantic
from typing import Optional, List
import logging
from passlib.context import CryptContext

logger = logging.getLogger("user_service")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserService:
    """
    Сервис для управления пользователями.
    Включает регистрацию, получение, обновление и удаление пользователей,
    а также проверку пароля.
    """

    @staticmethod
    async def create_user(username: str, password: str, email: Optional[str] = None,
                          is_active: bool = True, is_admin: bool = False) -> User_Pydantic:
        """
        Создает нового пользователя с хешированием пароля.
        Проверяет уникальность username и email.
        """
        if await User.exists(username=username):
            logger.error(f"Пользователь с логином '{username}' уже существует.")
            raise ValueError("Пользователь с таким логином уже существует")

        if email and await User.exists(email=email):
            logger.error(f"Пользователь с email '{email}' уже существует.")
            raise ValueError("Пользователь с таким email уже существует")

        hashed_password = pwd_context.hash(password)

        user_obj = await User.create(
            username=username,
            hashed_password=hashed_password,
            email=email,
            is_active=is_active,
            is_admin=is_admin,
        )
        logger.info(f"Создан пользователь {user_obj.id} с логином '{username}'.")
        return await User_Pydantic.from_tortoise_orm(user_obj)

    @staticmethod
    async def get_user(user_id: int) -> User_Pydantic:
        """
        Получить пользователя по ID.
        """
        user = await User.get_or_none(id=user_id)
        if not user:
            logger.error(f"Пользователь с id {user_id} не найден.")
            raise ValueError("Пользователь не найден")
        return await User_Pydantic.from_tortoise_orm(user)

    @staticmethod
    async def list_users(active_only: bool = True) -> List[User_Pydantic]:
        """
        Возвращает список пользователей, по умолчанию только активных.
        """
        query = User.all()
        if active_only:
            query = query.filter(is_active=True)
        users = await query.order_by("username").all()
        return await User_Pydantic.from_queryset(users)

    @staticmethod
    async def update_user(user_id: int, **kwargs) -> User_Pydantic:
        """
        Обновляет данные пользователя по переданным полям.
        Если обновляется пароль, автоматически хеширует его.
        """
        user = await User.get_or_none(id=user_id)
        if not user:
            logger.error(f"Попытка обновления несуществующего пользователя {user_id}.")
            raise ValueError("Пользователь не найден")

        password = kwargs.pop("password", None)
        if password:
            user.hashed_password = pwd_context.hash(password)

        for field, value in kwargs.items():
            if hasattr(user, field):
                setattr(user, field, value)

        try:
            await user.save()
            logger.info(f"Пользователь {user_id} успешно обновлен.")
        except IntegrityError as e:
            logger.error(f"Ошибка при обновлении пользователя {user_id}: {e}")
            raise ValueError("Ошибка обновления пользователя")

        return await User_Pydantic.from_tortoise_orm(user)

    @staticmethod
    async def delete_user(user_id: int) -> bool:
        """
        Удаляет пользователя по ID.
        """
        deleted_count = await User.filter(id=user_id).delete()
        if deleted_count == 0:
            logger.error(f"Попытка удаления несуществующего пользователя {user_id}.")
            raise ValueError("Пользователь не найден")
        logger.info(f"Пользователь {user_id} удален.")
        return True

    @staticmethod
    async def verify_user_password(username: str, password: str) -> bool:
        """
        Проверяет соответствие пароля пользователя.
        """
        user = await User.get_or_none(username=username)
        if not user:
            logger.error(f"Пользователь с логином '{username}' не найден при проверке пароля.")
            return False
        return pwd_context.verify(password, user.hashed_password)
