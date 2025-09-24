#!/bin/bash

set -euo pipefail

# Путь к terraform конфигурациям
TERRAFORM_DIR="$(dirname "$(realpath "$0")")"

# Проверка наличия terraform
if ! command -v terraform &> /dev/null; then
    echo "Ошибка: terraform не установлен или не доступен в PATH."
    exit 1
fi

echo "Запуск terraform apply в директории: $TERRAFORM_DIR"

cd "$TERRAFORM_DIR"

# Запуск terraform apply с автопринятием плана
terraform apply -auto-approve

echo "Terraform apply выполнен успешно."
