# DataFabric Core Frontend

Корпоративный веб-интерфейс для системы управления данными AetherNova DataFabric Core.

## 🚀 Возможности

- **Dashboard**: Мониторинг системы в реальном времени
- **Data Catalog**: Управление каталогом данных с поиском и фильтрацией
- **Pipelines**: Управление конвейерами обработки данных
- **Analytics**: Аналитика и отчетность
- **Governance**: Управление политиками и соответствие требованиям
- **Settings**: Конфигурация системы и пользовательские настройки

## 🛠 Технологический стек

### Основа
- **React 18** - Библиотека пользовательского интерфейса
- **TypeScript** - Типизированный JavaScript  
- **Vite** - Сборщик и dev-сервер

### UI/UX
- **Tailwind CSS** - Utility-first CSS фреймворк
- **Headless UI** - Доступные UI компоненты
- **Heroicons** - SVG иконки
- **Framer Motion** - Анимации

### Управление состоянием
- **Redux Toolkit** - Управление состоянием приложения
- **React Query** - Управление серверным состоянием

### Инструменты разработки
- **ESLint** - Линтер для JavaScript/TypeScript
- **Prettier** - Форматтер кода
- **Vitest** - Фреймворк тестирования

## 📁 Структура проекта

```
src/
├── components/          # Переиспользуемые компоненты
│   ├── common/         # Общие компоненты (Button, Input, Modal)
│   ├── layout/         # Компоненты макета (Header, Sidebar, Layout)
│   ├── charts/         # Компоненты графиков
│   ├── tables/         # Компоненты таблиц
│   ├── forms/          # Компоненты форм
│   ├── feedback/       # Компоненты обратной связи
│   ├── modals/         # Модальные окна
│   └── providers/      # Провайдеры контекста
├── pages/              # Страницы приложения
│   ├── dashboard/      # Дашборд
│   ├── catalog/        # Каталог данных
│   ├── pipelines/      # Управление пайплайнами
│   ├── analytics/      # Аналитика
│   ├── governance/     # Управление данными
│   └── settings/       # Настройки
├── services/           # Внешние сервисы
│   ├── api/           # API клиенты
│   ├── auth/          # Аутентификация
│   ├── websocket/     # WebSocket сервисы
│   └── storage/       # Локальное хранилище
├── hooks/             # Пользовательские хуки
├── utils/             # Утилиты
├── types/             # TypeScript типы
└── assets/            # Статические ресурсы
```

## 🚀 Быстрый старт

### Требования
- Node.js >= 18
- npm >= 8

### Установка

```bash
# Клонируйте репозиторий
cd /workspaces/aethernova/core-systems/datafabric-core/frontend

# Установите зависимости
npm install

# Запустите dev сервер
npm run dev

# Приложение будет доступно по адресу http://localhost:5173
```

## 📜 Доступные скрипты

```bash
# Разработка
npm run dev          # Запуск dev сервера
npm run build        # Сборка для продакшена
npm run preview      # Предпросмотр продакшен сборки

# Тестирование
npm run test         # Запуск тестов
npm run test:ui      # Запуск тестов с UI
npm run test:coverage # Запуск тестов с покрытием

# Линтинг
npm run lint         # Проверка кода
npm run lint:fix     # Исправление ошибок линтера

# Форматирование
npm run format       # Форматирование кода
```

## 🔧 Конфигурация

### Переменные окружения

Создайте файл `.env.local`:

```env
# API Configuration
VITE_API_BASE_URL=http://localhost:8000/api
VITE_WS_URL=ws://localhost:8000/ws

# Authentication
VITE_AUTH_ENABLED=true

# Features
VITE_ENABLE_ANALYTICS=true
VITE_ENABLE_GOVERNANCE=true
```

### Конфигурация Vite

Настройки в `vite.config.ts`:
- Алиасы путей (@components, @pages, @services, etc.)
- Прокси для API запросов
- Оптимизация для продакшена

### Конфигурация Tailwind

Кастомизация в `tailwind.config.js`:
- Цветовая схема
- Брейкпоинты
- Кастомные компоненты

## 🔐 Аутентификация

Система поддерживает:
- JWT токены
- Автоматическое обновление токенов
- Защищенные маршруты
- Управление ролями и разрешениями

## 📊 Мониторинг и аналитика

- Интеграция с WebSocket для real-time обновлений
- Дашборд для мониторинга системы
- Аналитические отчеты
- Алерты и уведомления

## 🧪 Тестирование

```bash
# Unit тесты
npm run test

# E2E тесты (будут добавлены)
npm run test:e2e

# Покрытие кода
npm run test:coverage
```

## 📦 Деплой

### Docker

```bash
# Сборка образа
docker build -t datafabric-frontend .

# Запуск контейнера
docker run -p 3000:80 datafabric-frontend
```

### Production Build

```bash
# Создание продакшен сборки
npm run build

# Файлы будут в папке dist/
```

## 🤝 Участие в разработке

1. Создайте ветку для новой функции
2. Внесите изменения
3. Добавьте тесты
4. Убедитесь что линтер не выдает ошибок
5. Создайте Pull Request

## 📝 Код стайл

Проект использует:
- ESLint для проверки кода
- Prettier для форматирования
- Husky для pre-commit хуков

## 🔗 Полезные ссылки

- [React Documentation](https://react.dev/)
- [TypeScript Documentation](https://www.typescriptlang.org/docs/)
- [Tailwind CSS Documentation](https://tailwindcss.com/docs)
- [Vite Documentation](https://vitejs.dev/guide/)

## 📄 Лицензия

MIT License - см. файл [LICENSE](LICENSE) для деталей.

## 🏗 Архитектура

### Компонентная архитектура
- Атомарный дизайн (Atoms, Molecules, Organisms)
- Переиспользуемые компоненты
- Композиция над наследованием

### Управление состоянием
- Redux Toolkit для глобального состояния
- React Query для серверного состояния
- Local state для компонентного состояния

### Типизация
- Строгая типизация TypeScript
- Типы для API ответов
- Типизированные хуки и утилиты

---

Разработано командой AetherNova для эффективного управления корпоративными данными.