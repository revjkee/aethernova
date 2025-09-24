from passlib.context import CryptContext

# Настройка контекста для безопасного хеширования паролей
pwd_context = CryptContext(
    schemes=["bcrypt", "argon2"],
    deprecated="auto",
    bcrypt__rounds=12
)

def hash_password(password: str) -> str:
    """
    Хеширует пароль с использованием bcrypt/argon2.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет соответствие пароля и хеша.
    """
    return pwd_context.verify(plain_password, hashed_password)
