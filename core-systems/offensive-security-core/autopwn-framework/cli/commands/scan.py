# autopwn-framework/cli/commands/scan.py

import asyncio
from autopwn_framework.utils.retry import retry_operation
from autopwn_framework.scanner import Scanner

async def scan_command(config_path: str):
    """
    Команда запуска сканирования по указанному конфигу.
    Использует retry-механику для повторного запуска при ошибках.
    """

    async def run_scan():
        scanner = Scanner(config_path)
        await scanner.load_config()
        await scanner.run()
        print(f"Сканирование завершено для конфигурации: {config_path}")

    await retry_operation(run_scan, retries=3, delay=5)
