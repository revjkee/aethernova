import asyncio
import logging
from typing import Optional
import wave
import contextlib

import aiohttp
import numpy as np
import librosa

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AudioTranscriber:
    def __init__(self, model_api_url: str, sample_rate: int = 16000):
        self.model_api_url = model_api_url
        self.sample_rate = sample_rate

    async def load_audio(self, filepath: str) -> np.ndarray:
        """
        Загружает аудио файл, конвертирует в моно и нужную частоту дискретизации.
        """
        try:
            audio, sr = librosa.load(filepath, sr=self.sample_rate, mono=True)
            logger.info(f"Audio loaded from {filepath} with sample rate {sr}")
            return audio
        except Exception as e:
            logger.error(f"Failed to load audio: {e}")
            raise

    async def transcribe(self, audio: np.ndarray) -> Optional[str]:
        """
        Отправляет аудиоданные на внешний API для транскрипции и возвращает текст.
        """
        try:
            async with aiohttp.ClientSession() as session:
                data = audio.tobytes()
                headers = {'Content-Type': 'application/octet-stream'}
                async with session.post(self.model_api_url, data=data, headers=headers) as resp:
                    if resp.status != 200:
                        logger.error(f"Transcription API returned status {resp.status}")
                        return None
                    result = await resp.json()
                    transcription = result.get("transcription")
                    logger.info("Transcription received")
                    return transcription
        except Exception as e:
            logger.error(f"Error during transcription: {e}")
            return None

    async def transcribe_file(self, filepath: str) -> Optional[str]:
        """
        Полный цикл: загрузка файла и отправка на транскрипцию.
        """
        audio = await self.load_audio(filepath)
        return await self.transcribe(audio)

# Пример использования
async def main():
    transcriber = AudioTranscriber(model_api_url="http://localhost:8000/api/transcribe")
    transcript = await transcriber.transcribe_file("sample_audio.wav")
    if transcript:
        print("Transcription result:")
        print(transcript)
    else:
        print("Failed to transcribe audio.")

if __name__ == "__main__":
    asyncio.run(main())
