#!/bin/bash
# Экстренный запуск sentinelwatch-core

echo "🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА SENTINELWATCH-CORE"
echo "⚠️  ВНИМАНИЕ: Система запускается в экстренном режиме восстановления"

# Проверка зависимостей
python -m pip install -r requirements.txt

# Экстренный запуск
python main.py

echo "🔒 Экстренный режим sentinelwatch-core завершен"
