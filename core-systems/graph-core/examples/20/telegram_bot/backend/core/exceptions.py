class AppBaseException(Exception):
    """
    Базовое исключение для всего приложения.
    Можно использовать для общего перехвата и логирования ошибок.
    """
    def __init__(self, message: str = "Произошла ошибка в приложении"):
        super().__init__(message)
        self.message = message


class ValidationError(AppBaseException):
    """
    Исключение для ошибок валидации данных.
    """
    def __init__(self, message: str = "Ошибка валидации данных"):
        super().__init__(message)


class DatabaseError(AppBaseException):
    """
    Исключение для ошибок работы с базой данных.
    """
    def __init__(self, message: str = "Ошибка базы данных"):
        super().__init__(message)


class NotFoundError(AppBaseException):
    """
    Исключение для ситуации, когда объект не найден.
    """
    def __init__(self, message: str = "Объект не найден"):
        super().__init__(message)


class UnauthorizedError(AppBaseException):
    """
    Исключение для ошибок авторизации и аутентификации.
    """
    def __init__(self, message: str = "Доступ запрещён"):
        super().__init__(message)
