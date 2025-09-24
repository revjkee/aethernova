# autopwn-framework/cli/main.py

import argparse
import asyncio
from autopwn_framework.utils.retry import retry_operation
from autopwn_framework.api.rest import start_rest_server
from autopwn_framework.api.websocket import app as websocket_app
from uvicorn import Config, Server

def parse_args():
    parser = argparse.ArgumentParser(description="Autopwn Framework CLI")
    parser.add_argument(
        "--mode",
        choices=["rest", "websocket", "scan", "help"],
        default="help",
        help="Режим работы: rest - запуск REST API, websocket - запуск WebSocket сервера, scan - запуск сканирования"
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Путь к конфигурационному файлу для сканирования"
    )
    return parser.parse_args()

async def run_rest():
    config = Config("autopwn_framework.api.rest:app", host="0.0.0.0", port=8000, log_level="info")
    server = Server(config)
    await server.serve()

async def run_websocket():
    config = Config("autopwn_framework.api.websocket:app", host="0.0.0.0", port=8001, log_level="info")
    server = Server(config)
    await server.serve()

async def run_scan(config_path):
    # Заглушка для запуска процесса сканирования с retry-механизмом
    async def scan_task():
        print(f"Запуск сканирования с конфигурацией: {config_path}")
        # Здесь должна быть логика запуска сканера
        await asyncio.sleep(3)
        print("Сканирование завершено")

    await retry_operation(scan_task, retries=3, delay=5)

async def main():
    args = parse_args()

    if args.mode == "rest":
        await run_rest()
    elif args.mode == "websocket":
        await run_websocket()
    elif args.mode == "scan":
        if not args.config:
            print("Для режима scan необходимо указать --config")
            return
        await run_scan(args.config)
    else:
        print("Используйте --mode [rest|websocket|scan] --config <path>")

if __name__ == "__main__":
    asyncio.run(main())
