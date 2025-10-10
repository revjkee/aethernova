#!/bin/bash
# Экстренный запуск quantumpulse-core

echo "🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА QUANTUMPULSE-CORE"
echo "⚠️  ВНИМАНИЕ: Система запускается в экстренном режиме восстановления"

# Проверка зависимостей
python -m pip install -r requirements.txt

# Экстренный запуск
python main.py

echo "🔒 Экстренный режим quantumpulse-core завершен"
