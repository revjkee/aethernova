from aiogram import Router
from backend.bot.handlers import user, admin
from backend.bot.middlewares import throttling, logging, error_handler, auth_middleware

# Основной роутер бота
router = Router()

# Подключаем middlewares
router.message.middleware(logging.LoggingMiddleware())      # Логирование сообщений
router.callback_query.middleware(logging.LoggingMiddleware())  # Логирование колбэков

router.message.middleware(throttling.ThrottlingMiddleware(limit=5, period=1))      # Антиспам для сообщений
router.callback_query.middleware(throttling.ThrottlingMiddleware(limit=5, period=1))  # Антиспам для колбэков

router.message.middleware(error_handler.ErrorHandlerMiddleware())       # Централизованная обработка ошибок
router.callback_query.middleware(error_handler.ErrorHandlerMiddleware())

router.message.middleware(auth_middleware.AuthMiddleware(allowed_user_ids={}))


router.callback_query.middleware(auth_middleware.AuthMiddleware(allowed_user_ids=set()))

# Подключаем обработчики
router.include_router(user.router)
router.include_router(admin.router)

def setup_bot_router() -> Router:
    return router