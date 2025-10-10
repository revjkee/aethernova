#!/bin/bash
# agent_mash/scripts/launch_integrated_system.sh

set -e

echo "🚀 Запуск интегрированной агентной системы AetherNova"
echo "=================================================="

# Определение путей
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AGENT_MASH_DIR="$PROJECT_ROOT/agent_mash"

echo "📁 Рабочая директория: $PROJECT_ROOT"
echo "🤖 Система агентов: $AGENT_MASH_DIR"

# Проверка существования core-систем
CORE_SYSTEMS_DIR="$PROJECT_ROOT/core-systems"
if [ -d "$CORE_SYSTEMS_DIR" ]; then
    echo "✅ Core-системы найдены: $CORE_SYSTEMS_DIR"
    
    # Проверка automation-core
    if [ -d "$CORE_SYSTEMS_DIR/automation-core" ]; then
        echo "✅ automation-core доступен"
    else
        echo "⚠️  automation-core не найден"
    fi
    
    # Проверка engine-core
    if [ -d "$CORE_SYSTEMS_DIR/engine-core" ]; then
        echo "✅ engine-core доступен"
    else
        echo "⚠️  engine-core не найден"
    fi
    
    # Проверка ai-platform-core
    if [ -d "$CORE_SYSTEMS_DIR/ai-platform-core" ]; then
        echo "✅ ai-platform-core доступен"
    else
        echo "⚠️  ai-platform-core не найден"
    fi
else
    echo "❌ Core-системы не найдены в $CORE_SYSTEMS_DIR"
    echo "   Система будет работать в автономном режиме"
fi

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 не установлен"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "🐍 Python версия: $PYTHON_VERSION"

# Проверка зависимостей
echo "📦 Проверка зависимостей..."

cd "$AGENT_MASH_DIR"

# Создание виртуального окружения если не существует
if [ ! -d "venv" ]; then
    echo "🏗️  Создание виртуального окружения..."
    python3 -m venv venv
fi

# Активация виртуального окружения
source venv/bin/activate
echo "✅ Виртуальное окружение активировано"

# Установка зависимостей если requirements изменились
if [ ! -f "venv/.deps_installed" ] || [ requirements.txt -nt "venv/.deps_installed" ]; then
    echo "📥 Установка зависимостей..."
    pip install -r requirements.txt
    touch venv/.deps_installed
else
    echo "✅ Зависимости уже установлены"
fi

# Проверка конфигурации
CONFIG_FILE="$AGENT_MASH_DIR/config/core_integration.yaml"
if [ -f "$CONFIG_FILE" ]; then
    echo "✅ Конфигурация найдена: $CONFIG_FILE"
else
    echo "❌ Конфигурация не найдена: $CONFIG_FILE"
    exit 1
fi

# Установка переменных окружения
export PYTHONPATH="$PROJECT_ROOT:$AGENT_MASH_DIR:$PYTHONPATH"
export AETHERNOVA_CONFIG="$CONFIG_FILE"
export AETHERNOVA_PROJECT_ROOT="$PROJECT_ROOT"

# Опциональные переменные окружения
export JWT_SECRET_KEY="${JWT_SECRET_KEY:-default-secret-key-change-in-production}"
export ENCRYPTION_KEY="${ENCRYPTION_KEY:-default-encryption-key-change-in-production}"
export DATABASE_URL="${DATABASE_URL:-sqlite:///./dev.db}"

echo "🔧 Переменные окружения настроены"

# Проверка портов
check_port() {
    local port=$1
    local name=$2
    
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        echo "⚠️  Порт $port ($name) занят"
        return 1
    else
        echo "✅ Порт $port ($name) свободен"
        return 0
    fi
}

echo "🔍 Проверка портов..."
check_port 8000 "engine-core API" || echo "   Будет использован следующий доступный порт"
check_port 8080 "monitoring dashboard" || echo "   Будет использован следующий доступный порт"
check_port 9090 "prometheus metrics" || echo "   Будет использован следующий доступный порт"

# Опциональный запуск engine-core
ENGINE_CORE_SCRIPT="$CORE_SYSTEMS_DIR/engine-core/src/main.py"
if [ -f "$ENGINE_CORE_SCRIPT" ] && [ "${START_ENGINE_CORE:-false}" = "true" ]; then
    echo "🚀 Запуск engine-core..."
    cd "$CORE_SYSTEMS_DIR/engine-core"
    python3 src/main.py --host 0.0.0.0 --port 8000 &
    ENGINE_CORE_PID=$!
    echo "✅ engine-core запущен (PID: $ENGINE_CORE_PID)"
    
    # Ожидание готовности engine-core
    echo "⏳ Ожидание готовности engine-core..."
    for i in {1..30}; do
        if curl -s http://localhost:8000/health >/dev/null 2>&1; then
            echo "✅ engine-core готов"
            break
        fi
        sleep 1
    done
fi

cd "$AGENT_MASH_DIR"

# Функция очистки при завершении
cleanup() {
    echo "🧹 Очистка..."
    if [ ! -z "$ENGINE_CORE_PID" ]; then
        echo "🛑 Остановка engine-core (PID: $ENGINE_CORE_PID)"
        kill $ENGINE_CORE_PID 2>/dev/null || true
    fi
    
    # Остановка всех фоновых процессов агентной системы
    pkill -f "integrated_agent_system.py" 2>/dev/null || true
    
    echo "✅ Очистка завершена"
}

# Установка обработчика сигналов
trap cleanup EXIT INT TERM

# Основной запуск интегрированной системы
echo ""
echo "🎯 ЗАПУСК ИНТЕГРИРОВАННОЙ АГЕНТНОЙ СИСТЕМЫ"
echo "========================================="

# Запуск с различными опциями
case "${1:-normal}" in
    "demo")
        echo "🎮 Режим демонстрации"
        python3 scripts/integrated_agent_system.py --mode demo
        ;;
    "test") 
        echo "🧪 Тестовый режим"
        python3 scripts/integrated_agent_system.py --mode test
        ;;
    "benchmark")
        echo "📊 Режим бенчмарка"
        python3 scripts/integrated_agent_system.py --mode benchmark
        ;;
    "monitor")
        echo "📡 Режим только мониторинга"
        python3 scripts/integrated_agent_system.py --mode monitor
        ;;
    *)
        echo "🚀 Стандартный режим"
        python3 scripts/integrated_agent_system.py
        ;;
esac

echo "✅ Интегрированная система завершена"