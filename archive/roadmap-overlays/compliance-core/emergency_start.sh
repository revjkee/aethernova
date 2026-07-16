#!/bin/bash
# Экстренный запуск compliance-core

echo "🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА COMPLIANCE-CORE"
echo "⚠️  ВНИМАНИЕ: Система запускается в экстренном режиме восстановления"

# Проверка зависимостей
python -m pip install -r requirements.txt

# Экстренный запуск
python main.py

echo "🔒 Экстренный режим compliance-core завершен"
