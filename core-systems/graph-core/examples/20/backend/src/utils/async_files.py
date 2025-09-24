import asyncio
from pathlib import Path
from typing import Union, Optional


class AsyncFileHandler:
    """
    Асинхронный обработчик файлов для чтения и записи с использованием asyncio.
    """

    def __init__(self, filepath: Union[str, Path], mode: str = 'r', encoding: Optional[str] = 'utf-8'):
        self.filepath = Path(filepath)
        self.mode = mode
        self.encoding = encoding
        self._file = None

    async def __aenter__(self):
        loop = asyncio.get_event_loop()
        self._file = await loop.run_in_executor(None, self.filepath.open, self.mode, self.encoding)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._file.close)

    async def read(self) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._file.read)

    async def write(self, data: str):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._file.write, data)
        await loop.run_in_executor(None, self._file.flush)

    async def read_lines(self):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._file.readlines)

    async def write_lines(self, lines):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._file.writelines, lines)
        await loop.run_in_executor(None, self._file.flush)
