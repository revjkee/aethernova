engine-core/codegen/python/v1/README.md

markdown
Копировать
Редактировать
# Engine-Core Codegen Python V1

Промышленный модуль генерации Python-кода на базе gRPC/Protocol Buffers и шаблонов.
Используется в архитектуре **engine-core** для автоматической генерации API, DTO и вспомогательных модулей.

---

## 📌 Возможности
- Генерация Python-классов из `.proto` файлов (gRPC + Protobuf).
- Автоматическая генерация type hints через `mypy-protobuf`.
- Поддержка шаблонов Jinja2 для кастомной генерации кода.
- Автоматическое форматирование (`black`, `isort`, `autoflake`).
- Линтинг и анализ безопасности (`ruff`, `bandit`).
- Интеграция с CI/CD и версиями SemVer.
- Поддержка live-reload при изменении файлов (`watchdog`).

---

## 📂 Структура директории
engine-core/
└── codegen/
└── python/
└── v1/
├── VERSION # Версия генератора
├── VERSION_META.json # Метаданные версии
├── requirements.txt # Зависимости
├── README.md # Документация
├── templates/ # Шаблоны для генерации
├── scripts/ # CLI-скрипты генератора
└── generated/ # Папка для сгенерированного кода

yaml
Копировать
Редактировать

---

## 🚀 Установка
```bash
# Клонирование репозитория
git clone https://github.com/your-org/engine-core.git
cd engine-core/codegen/python/v1

# Установка зависимостей
pip install -r requirements.txt
⚙️ Запуск генерации
bash
Копировать
Редактировать
python scripts/codegen.py \
  --proto-dir ./protos \
  --output-dir ./generated \
  --templates ./templates \
  --lint
Параметры:

--proto-dir — путь к директории с .proto файлами.

--output-dir — папка для сохранения сгенерированного кода.

--templates — путь к кастомным шаблонам Jinja2.

--lint — автоформатирование и линтинг после генерации.

🧪 Тестирование
bash
Копировать
Редактировать
pytest --cov=./generated
🔄 CI/CD Интеграция
Добавьте шаг в GitHub Actions:

yaml
Копировать
Редактировать
- name: Run Python Codegen
  run: |
    cd engine-core/codegen/python/v1
    python scripts/codegen.py --proto-dir ./protos --output-dir ./generated --lint
🔒 Рекомендации по безопасности
Проверяйте .proto файлы на наличие вредоносных изменений перед генерацией.

Запускайте линтер и bandit для проверки кода.

Используйте фиксированные версии зависимостей в constraints.txt.

📜 Лицензия
MIT / Apache 2.0 (в зависимости от политики проекта)

© 2025 Engine-Core Codegen Team