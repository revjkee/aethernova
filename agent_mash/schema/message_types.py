# agent-mesh/schema/message_types.py

from enum import Enum


class MessageType(str, Enum):
    """
    Перечисление стандартных типов сообщений между агентами:
    - TASK: запрос на выполнение действия (основной)
    - EVENT: асинхронное событие среды или системы
    - RESULT: результат обработки запроса/цели
    - ERROR: сообщение об ошибке или сбое
    """

    TASK = "task"
    EVENT = "event"
    RESULT = "result"
    ERROR = "error"


def is_valid_message_type(value: str) -> bool:
    """
    Проверяет, является ли строка допустимым типом сообщения
    """
    return value in MessageType.__members__.values()


def describe_message_type(msg_type: MessageType) -> str:
    """
    Возвращает описание для UI, логирования или документации
    """
    return {
        MessageType.TASK: "Запрос на выполнение задачи",
        MessageType.EVENT: "Системное или внешнее событие",
        MessageType.RESULT: "Результат выполнения запроса",
        MessageType.ERROR: "Ошибка или сбой выполнения"
    }.get(msg_type, "Неизвестный тип")
