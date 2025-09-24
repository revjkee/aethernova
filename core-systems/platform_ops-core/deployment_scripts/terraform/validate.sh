#!/bin/bash

set -euo pipefail

# Путь к terraform конфигурациям
TERRAFORM_DIR="$(dirname "$(realpath "$0")")"

# Проверка наличия terraform
if ! command -v terraform &> /dev/null; then
    echo "Ошибка: terraform не установлен или не доступен в PATH."
    exit 1
fi

echo "Запуск terraform validate в директории: $TERRAFORM_DIR"

cd "$TERRAFORM_DIR"

# Инициализация terraform без скачивания плагинов (для быстрой проверки)
terraform init -backend=false

# Запуск проверки конфигурации terraform
terraform validate

echo "Terraform validate прошел успешно."
