#!/usr/bin/env bash

set -euo pipefail

# validators.sh — набор функций для проверки окружения и параметров перед деплоем

# Проверка, что обязательная переменная окружения установлена и не пустая
function validate_env_var() {
    local var_name=$1
    if [ -z "${!var_name:-}" ]; then
        echo "ERROR: Environment variable '$var_name' is not set or empty." >&2
        exit 1
    fi
}

# Проверка, что команда доступна в PATH
function validate_command() {
    local cmd=$1
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: Required command '$cmd' not found in PATH." >&2
        exit 1
    fi
}

# Проверка, что файл существует и доступен для чтения
function validate_file_readable() {
    local file_path=$1
    if [ ! -f "$file_path" ] || [ ! -r "$file_path" ]; then
        echo "ERROR: File '$file_path' does not exist or is not readable." >&2
        exit 1
    fi
}

# Проверка, что директория существует и доступна для записи
function validate_directory_writable() {
    local dir_path=$1
    if [ ! -d "$dir_path" ] || [ ! -w "$dir_path" ]; then
        echo "ERROR: Directory '$dir_path' does not exist or is not writable." >&2
        exit 1
    fi
}

# Проверка валидности IP адреса (IPv4)
function validate_ipv4() {
    local ip=$1
    if [[ ! $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "ERROR: '$ip' is not a valid IPv4 address." >&2
        exit 1
    fi
    # Проверка каждого октета на диапазон 0-255
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if ((octet < 0 || octet > 255)); then
            echo "ERROR: '$ip' has invalid octet value." >&2
            exit 1
        fi
    done
}

# Проверка, что число — положительное целое
function validate_positive_integer() {
    local val=$1
    if ! [[ "$val" =~ ^[1-9][0-9]*$ ]]; then
        echo "ERROR: Value '$val' is not a valid positive integer." >&2
        exit 1
    fi
}

# Проверка, что значение равно одному из разрешенных
function validate_enum() {
    local val=$1
    shift
    local allowed=("$@")
    for allowed_val in "${allowed[@]}"; do
        if [[ "$val" == "$allowed_val" ]]; then
            return 0
        fi
    done
    echo "ERROR: Value '$val' is not one of allowed: ${allowed[*]}" >&2
    exit 1
}

# Вывод помощи по используемым валидаторам
function print_validators_help() {
    cat << EOF
validators.sh - функции для валидации параметров деплоя

Использование функций:
- validate_env_var VAR_NAME
- validate_command CMD_NAME
- validate_file_readable FILE_PATH
- validate_directory_writable DIR_PATH
- validate_ipv4 IP_ADDRESS
- validate_positive_integer VALUE
- validate_enum VALUE ALLOWED_VALUES...

Пример:
  validate_env_var DEPLOY_ENV
  validate_command kubectl
EOF
}

# Если скрипт запущен напрямую, вывести помощь
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    print_validators_help
    exit 0
fi
