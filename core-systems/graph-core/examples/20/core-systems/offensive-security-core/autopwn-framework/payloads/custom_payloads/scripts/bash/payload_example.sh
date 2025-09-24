#!/bin/bash
#
# payload_example.sh
#
# Пример простого bash payload скрипта.
# Демонстрирует базовую структуру:
# - Объявление переменных
# - Основная логика
# - Обработка ошибок
#

TARGET="127.0.0.1"

echo "Запуск bash payload для цели: $TARGET"

# Основная логика payload (пример)
if ping -c 1 "$TARGET" &> /dev/null
then
    echo "Цель $TARGET доступна"
else
    echo "Не удалось достучаться до цели $TARGET" >&2
    exit 1
fi

echo "Payload выполнен успешно."
exit 0
