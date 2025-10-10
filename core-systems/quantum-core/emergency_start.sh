#!/bin/bash
# Экстренный запуск quantum-core

echo "🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА QUANTUM-CORE"
echo "⚠️  ВНИМАНИЕ: Система запускается в экстренном режиме восстановления"

# Проверка зависимостей
python -m pip install -r requirements.txt

# Экстренный запуск
python main.py

echo "🔒 Экстренный режим quantum-core завершен"
