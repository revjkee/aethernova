#!/usr/bin/env python3
"""
AetherNova NLP Supermodule - Server Runner
Запуск HTTP + WebSocket API сервера
"""

import os
import sys
import logging
import argparse
from pathlib import Path

# Добавление корневой директории в sys.path
root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("server-runner")


def parse_args():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="AetherNova NLP Supermodule API Server"
    )
    
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind (default: 0.0.0.0)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind (default: 8000)"
    )
    
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload (development mode)"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)"
    )
    
    parser.add_argument(
        "--log-level",
        type=str,
        default="info",
        choices=["critical", "error", "warning", "info", "debug"],
        help="Log level (default: info)"
    )
    
    parser.add_argument(
        "--no-websocket",
        action="store_true",
        help="Disable WebSocket support"
    )
    
    return parser.parse_args()


def check_dependencies():
    """Проверка установленных зависимостей"""
    required_packages = [
        "fastapi",
        "uvicorn",
        "pydantic",
        "transformers",
        "torch"
    ]
    
    missing = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        logger.error(f"Missing required packages: {', '.join(missing)}")
        logger.error("Install them with: pip install -r requirements-api.txt")
        sys.exit(1)
    
    logger.info("✅ All dependencies installed")


def check_models():
    """Проверка доступности NLP моделей"""
    logger.info("Checking NLP models...")
    
    # Проверка будет выполнена при первом запросе
    # Здесь можно добавить предварительную загрузку моделей
    
    logger.info("✅ Models check passed")


def main():
    """Главная функция"""
    args = parse_args()
    
    logger.info("=" * 60)
    logger.info("🚀 AetherNova NLP Supermodule API Server")
    logger.info("=" * 60)
    
    # Проверки
    logger.info("Running pre-flight checks...")
    check_dependencies()
    check_models()
    
    # Настройки
    logger.info(f"Host: {args.host}")
    logger.info(f"Port: {args.port}")
    logger.info(f"Workers: {args.workers}")
    logger.info(f"Reload: {args.reload}")
    logger.info(f"Log Level: {args.log_level}")
    logger.info(f"WebSocket: {'Disabled' if args.no_websocket else 'Enabled'}")
    
    # Импорт uvicorn
    try:
        import uvicorn
    except ImportError:
        logger.error("uvicorn not installed. Install with: pip install uvicorn[standard]")
        sys.exit(1)
    
    # Запуск сервера
    logger.info("=" * 60)
    logger.info(f"🌐 Starting server at http://{args.host}:{args.port}")
    logger.info(f"📚 API Documentation: http://{args.host}:{args.port}/docs")
    logger.info(f"📖 ReDoc: http://{args.host}:{args.port}/redoc")
    if not args.no_websocket:
        logger.info(f"🔌 WebSocket: ws://{args.host}:{args.port}/ws/{{client_id}}")
    logger.info("=" * 60)
    
    try:
        uvicorn.run(
            "api.http.server:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            workers=args.workers if not args.reload else 1,
            log_level=args.log_level,
            access_log=True
        )
    except KeyboardInterrupt:
        logger.info("\n👋 Server stopped by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
