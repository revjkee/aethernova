#!/bin/bash
# Экстренный запуск aethernova-chain-core

echo "🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА AETHERNOVA-CHAIN-CORE"
echo "⚠️  ВНИМАНИЕ: Система запускается в экстренном режиме восстановления"

# Проверка зависимостей
python -m pip install -r requirements.txt

# Экстренный запуск
python main.py

echo "🔒 Экстренный режим aethernova-chain-core завершен"
