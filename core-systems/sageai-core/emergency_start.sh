#!/bin/bash
# Экстренный запуск sageai-core

echo "🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА SAGEAI-CORE"
echo "⚠️  ВНИМАНИЕ: Система запускается в экстренном режиме восстановления"

# Проверка зависимостей
python -m pip install -r requirements.txt

# Экстренный запуск
python main.py

echo "🔒 Экстренный режим sageai-core завершен"
