# telegram-bot/ai-assistant/voice_handler.py

import asyncio
import speech_recognition as sr
from typing import Optional

class VoiceHandler:
    """
    Модуль для обработки голосовых сообщений:
    - преобразование речи в текст
    - поддержка асинхронной обработки
    - управление ошибками распознавания
    """

    def __init__(self, recognizer: Optional[sr.Recognizer] = None, microphone: Optional[sr.Microphone] = None):
        self.recognizer = recognizer or sr.Recognizer()
        self.microphone = microphone or sr.Microphone()

    async def recognize_from_audio_file(self, audio_file_path: str) -> Optional[str]:
        """
        Асинхронное распознавание речи из аудиофайла.
        :param audio_file_path: путь к аудиофайлу (wav, flac, mp3 и др.)
        :return: распознанный текст или None в случае ошибки
        """
        loop = asyncio.get_running_loop()
        try:
            with sr.AudioFile(audio_file_path) as source:
                audio_data = self.recognizer.record(source)
            text = await loop.run_in_executor(None, self.recognizer.recognize_google, audio_data)
            return text.strip()
        except sr.UnknownValueError:
            return None  # речь не распознана
        except sr.RequestError as e:
            # Ошибка сервиса распознавания (например, проблема с сетью)
            print(f"Recognition service error: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error during voice recognition: {e}")
            return None

    async def recognize_from_microphone(self, timeout: float = 5.0, phrase_time_limit: float = 10.0) -> Optional[str]:
        """
        Асинхронное распознавание речи с микрофона.
        :param timeout: максимальное время ожидания начала речи
        :param phrase_time_limit: максимальная длительность фразы
        :return: распознанный текст или None в случае ошибки
        """
        loop = asyncio.get_running_loop()
        try:
            with self.microphone as source:
                self.recognizer.adjust_for_ambient_noise(source, duration=1)
                audio = await loop.run_in_executor(None, lambda: self.recognizer.listen(source, timeout=timeout, phrase_time_limit=phrase_time_limit))
            text = await loop.run_in_executor(None, self.recognizer.recognize_google, audio)
            return text.strip()
        except sr.WaitTimeoutError:
            print("Timeout waiting for speech.")
            return None
        except sr.UnknownValueError:
            print("Could not understand audio.")
            return None
        except sr.RequestError as e:
            print(f"Recognition service error: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error during voice recognition: {e}")
            return None

# Пример использования
if __name__ == "__main__":
    import sys

    async def main():
        handler = VoiceHandler()

        if len(sys.argv) > 1:
            audio_path = sys.argv[1]
            print(f"Распознавание из файла: {audio_path}")
            text = await handler.recognize_from_audio_file(audio_path)
            if text:
                print(f"Распознанный текст:\n{text}")
            else:
                print("Речь не распознана.")
        else:
            print("Распознавание с микрофона. Говорите что-нибудь...")
            text = await handler.recognize_from_microphone()
            if text:
                print(f"Распознанный текст:\n{text}")
            else:
                print("Речь не распознана или произошла ошибка.")

    asyncio.run(main())
