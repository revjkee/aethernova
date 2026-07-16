#!/bin/bash
# Экстренный запуск genesisops-core

echo "🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА GENESISOPS-CORE"
echo "⚠️  ВНИМАНИЕ: Система запускается в экстренном режиме восстановления"

# Проверка зависимостей
python -m pip install -r requirements.txt

# Экстренный запуск
python main.py

echo "🔒 Экстренный режим genesisops-core завершен"
