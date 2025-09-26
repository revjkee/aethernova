from src.auth.password_hasher import hash_password as _hash, verify_password as _verify

class PasswordHasher:
    def hash_password(self, password: str) -> str:
        return _hash(password)

    def verify_password(self, plain: str, hashed: str) -> bool:
        return _verify(plain, hashed)
