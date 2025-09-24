# File: exploits/payloads/http_upload.py

import requests
from typing import Optional

from exploits.payloads.payload_base import PayloadBase


class HTTPUploadPayload(PayloadBase):
    """
    Payload для загрузки файлов на целевой сервер через HTTP(S) POST-запрос.

    Используется для доставки полезной нагрузки или выполнения дополнительных действий
    на сервере через уязвимые HTTP-интерфейсы загрузки.
    """

    def __init__(self, target: str, port: int, upload_url: str, file_path: str):
        """
        Инициализация полезной нагрузки HTTP upload.

        :param target: адрес цели
        :param port: порт цели
        :param upload_url: полный URL для загрузки файла на целевой сервер
        :param file_path: локальный путь к файлу, который нужно загрузить
        """
        super().__init__(target, port)
        self.upload_url = upload_url
        self.file_path = file_path

    def prepare(self) -> bool:
        """
        Проверка доступности URL для загрузки и файла.

        :return: True — если файл существует и URL валидный
        """
        try:
            # Проверяем локальный файл
            with open(self.file_path, "rb"):
                pass
            # Проверяем доступность URL (HEAD-запрос)
            response = requests.head(self.upload_url, timeout=5)
            return response.status_code < 400
        except Exception:
            return False

    def execute(self) -> bool:
        """
        Загружает файл на целевой сервер через HTTP POST.

        :return: True — если загрузка прошла успешно (код 200 или 201)
        """
        try:
            with open(self.file_path, "rb") as f:
                files = {"file": (self.file_path, f)}
                response = requests.post(self.upload_url, files=files, timeout=15)
                return response.status_code in (200, 201)
        except Exception:
            return False

    def cleanup(self) -> None:
        """
        Очистка после выполнения (если требуется).

        Для HTTP загрузки обычно не нужна.
        """
        pass
