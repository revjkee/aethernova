# 🧪 Lab OS — Laboratory Management System

**Lab OS** — это комплексная система для управления лабораторией, экспериментами, ресурсами, коллаборацией и анализом данных.

## 📦 Основные модули
- labos_core.py — ядро управления лабораторией
- experiment.py — управление экспериментами
- resource_manager.py — аллокация и мониторинг ресурсов
- collaboration.py — инструменты совместной работы
- data_analysis.py — интеграция с аналитикой
- dashboard.py — визуализация и метрики
- api.py — REST API + WebSocket
- tests/ — 60+ тестов
- deployment/ — Docker/Kubernetes конфиги

## 🚀 Быстрый старт
```bash
pip install -r requirements.txt
python api.py
```

## 🏗️ Архитектура
```
lab-os/
├── labos_core.py
├── experiment.py
├── resource_manager.py
├── collaboration.py
├── data_analysis.py
├── dashboard.py
├── api.py
├── tests/
├── deployment/
└── README.md
```

## 🔬 Возможности
- Управление лабораторией и экспериментами
- Аллокация CPU/GPU/RAM/Storage
- Коллаборация: добавление/удаление участников
- Автоматизация: workflow, notifications
- Интеграция с аналитикой и ML
- Визуализация метрик и статуса
- REST API + WebSocket для интеграции

## 🧪 Тесты
```bash
pytest tests/ -v
```

## 🚢 Деплой
```bash
docker-compose -f deployment/docker-compose.yml up -d
```

## 📈 Метрики
- experiments_total
- resources_allocated
- active_users
- analysis_jobs

## 📄 Лицензия
MIT
