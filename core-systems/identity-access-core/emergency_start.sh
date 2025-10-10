#!/bin/bash
# Экстренный запуск identity-access-core

echo "🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА IDENTITY-ACCESS-CORE"
echo "⚠️  ВНИМАНИЕ: Система запускается в экстренном режиме восстановления"

# Проверка зависимостей
python -m pip install -r requirements.txt

# Экстренный запуск
python main.py

echo "🔒 Экстренный режим identity-access-core завершен"
