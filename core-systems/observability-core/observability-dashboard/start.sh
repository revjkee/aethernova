#!/bin/bash

# AetherNova Observability Dashboard - Быстрый запуск
# Автоматическая установка и запуск веб-интерфейса для observability-core

set -e

echo "🚀 AetherNova Observability Dashboard - Запуск установки..."

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для цветного вывода
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Проверка Node.js
check_node() {
    log_info "Проверка Node.js..."
    if ! command -v node &> /dev/null; then
        log_error "Node.js не найден! Установите Node.js 18+ для продолжения."
        exit 1
    fi
    
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        log_error "Требуется Node.js версии 18+. Текущая версия: $(node -v)"
        exit 1
    fi
    
    log_success "Node.js $(node -v) найден"
}

# Проверка npm
check_npm() {
    log_info "Проверка npm..."
    if ! command -v npm &> /dev/null; then
        log_error "npm не найден!"
        exit 1
    fi
    log_success "npm $(npm -v) найден"
}

# Установка зависимостей
install_dependencies() {
    log_info "Установка зависимостей..."
    cd /workspaces/aethernova/core-systems/observability-core/observability-dashboard
    
    if [ ! -f "package.json" ]; then
        log_error "package.json не найден!"
        exit 1
    fi
    
    npm install
    log_success "Зависимости установлены"
}

# Проверка сервисов
check_services() {
    log_info "Проверка доступности observability сервисов..."
    
    # Проверка Prometheus
    if curl -f -s http://localhost:9090/api/v1/status/config > /dev/null 2>&1; then
        log_success "Prometheus (9090) - доступен"
    else
        log_warning "Prometheus (9090) - недоступен"
    fi
    
    # Проверка Grafana
    if curl -f -s http://localhost:3000/api/health > /dev/null 2>&1; then
        log_success "Grafana (3000) - доступен"
    else
        log_warning "Grafana (3000) - недоступен"
    fi
    
    # Проверка Kibana
    if curl -f -s http://localhost:5601/api/status > /dev/null 2>&1; then
        log_success "Kibana (5601) - доступен"
    else
        log_warning "Kibana (5601) - недоступен"
    fi
}

# Сборка проекта
build_project() {
    log_info "Сборка проекта..."
    npm run build
    log_success "Проект собран успешно"
}

# Запуск в режиме разработки
start_dev() {
    log_info "Запуск в режиме разработки..."
    log_success "Dashboard будет доступен по адресу: http://localhost:3000"
    log_info "Для остановки нажмите Ctrl+C"
    npm run dev
}

# Главная функция
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           AetherNova Observability Dashboard             ║"
    echo "║                   Быстрый запуск                        ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_node
    check_npm
    install_dependencies
    check_services
    
    echo ""
    log_info "Выберите режим запуска:"
    echo "1) Режим разработки (dev)"
    echo "2) Сборка для продакшена (build)"
    echo "3) Выход"
    
    read -p "Ваш выбор [1-3]: " choice
    
    case $choice in
        1)
            start_dev
            ;;
        2)
            build_project
            log_success "Файлы собраны в папку dist/"
            ;;
        3)
            log_info "Выход..."
            exit 0
            ;;
        *)
            log_error "Неверный выбор!"
            exit 1
            ;;
    esac
}

# Обработка сигналов
trap 'log_info "Остановка..."; exit 0' INT TERM

# Запуск
main