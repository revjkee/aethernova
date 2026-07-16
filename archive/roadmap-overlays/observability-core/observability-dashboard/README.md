# AetherNova Observability Dashboard

Современный веб-интерфейс для мониторинга и аналитики observability-core системы AetherNova.

## 🚀 Возможности

- **Real-time мониторинг** - Живые метрики от Prometheus
- **Grafana интеграция** - Встроенные dashboards и панели
- **Система алертов** - Управление уведомлениями
- **Поиск логов** - Интеграция с ELK Stack
- **Темная тема** - Адаптивный дизайн
- **Responsive UI** - Поддержка мобильных устройств

## 🛠 Технический стек

- **Frontend**: React 18 + TypeScript + Vite
- **Styling**: Tailwind CSS
- **Charts**: Chart.js + Recharts
- **Icons**: Lucide React
- **HTTP Client**: Axios
- **Routing**: React Router DOM

## 📁 Структура проекта

```
observability-dashboard/
├── src/
│   ├── components/          # UI компоненты
│   │   ├── Header.tsx       # Заголовок с навигацией
│   │   ├── Sidebar.tsx      # Боковое меню
│   │   └── GrafanaPanel.tsx # Встраивание Grafana панелей
│   ├── pages/               # Страницы приложения
│   │   ├── Dashboard.tsx    # Главная панель
│   │   ├── Metrics.tsx      # Метрики и графики
│   │   ├── Logs.tsx         # Просмотр логов
│   │   ├── Alerts.tsx       # Управление алертами
│   │   └── Settings.tsx     # Настройки
│   ├── services/            # API сервисы
│   │   ├── grafanaService.ts    # Grafana API
│   │   └── prometheusService.ts # Prometheus API
│   ├── hooks/               # React хуки
│   │   └── useMetrics.ts    # Хуки для метрик
│   ├── App.tsx              # Главный компонент
│   ├── main.tsx             # Точка входа
│   └── index.css            # Глобальные стили
├── public/                  # Статические файлы
├── package.json             # Зависимости
├── vite.config.ts           # Конфигурация Vite
├── tailwind.config.js       # Конфигурация Tailwind
└── tsconfig.json            # Конфигурация TypeScript
```

## 🔧 Установка и запуск

### Предварительные требования

- Node.js 18+ 
- npm или yarn
- Запущенные сервисы: Prometheus (9090), Grafana (3000), Kibana (5601)

### Установка зависимостей

```bash
cd observability-dashboard
npm install
```

### Запуск в режиме разработки

```bash
npm run dev
```

Приложение будет доступно по адресу: http://localhost:3000

### Сборка для продакшена

```bash
npm run build
```

## 🌐 API Интеграции

### Prometheus (порт 9090)
- `/api/prometheus/api/v1/query` - Мгновенные запросы
- `/api/prometheus/api/v1/query_range` - Диапазонные запросы
- `/api/prometheus/api/v1/labels` - Получение меток

### Grafana (порт 3000)
- `/api/grafana/api/dashboards/uid/{uid}` - Получение dashboard
- `/api/grafana/d-solo/{uid}` - Встраивание панелей
- `/api/grafana/api/search` - Поиск dashboards

### Kibana (порт 5601)
- `/api/kibana/api/saved_objects` - Работа с логами
- `/api/kibana/api/console/proxy` - Поиск по индексам

## 📊 Основные метрики

### Системные метрики:
- CPU Usage (загрузка процессора)
- Memory Usage (использование памяти) 
- Disk Usage (использование диска)
- Network I/O (сетевая активность)

### AetherNova метрики:
- Active Agents (активные агенты): 315
- Response Time (время отклика): ~45ms
- System Health (здоровье системы): 98.5%
- Active Alerts (активные алерты): 3

## 🎨 Компоненты UI

### GrafanaPanel
Встраивание Grafana панелей в React приложение:

```tsx
<GrafanaPanel
  dashboardUid="teslaai-core"
  panelId={1}
  title="CPU Metrics"
  height={400}
  theme="light"
  timeRange={{ from: 'now-1h', to: 'now' }}
/>
```

### useMetrics hooks
React хуки для получения метрик:

```tsx
const { metrics, loading, error } = useSystemMetrics(30000);
const { metrics: aetherMetrics } = useAetherNovaMetrics();
```

## 🛡 Безопасность

- CORS настройки для API endpoints
- Проксирование запросов через Vite dev server
- Защищенные соединения с observability сервисами

## 🚀 Деплой

### Docker деплой
```bash
# Сборка образа
docker build -t aethernova-observability-dashboard .

# Запуск контейнера
docker run -p 3000:3000 aethernova-observability-dashboard
```

### Nginx конфигурация
```nginx
location /api/prometheus/ {
    proxy_pass http://localhost:9090/;
}

location /api/grafana/ {
    proxy_pass http://localhost:3000/;
}

location /api/kibana/ {
    proxy_pass http://localhost:5601/;
}
```

## 📈 Мониторинг производительности

- Автоматическое обновление метрик каждые 30 секунд
- Lazy loading для тяжелых компонентов
- Оптимизированные сборки с code splitting
- Service Worker для кэширования

## 🔧 Кастомизация

### Темы
Поддержка светлой и темной темы через Tailwind CSS:

```css
.dark .card {
  @apply bg-gray-800 text-white;
}
```

### Метрики
Добавление новых метрик в `prometheusService.ts`:

```typescript
async getCustomMetric(): Promise<number> {
  const response = await this.query('your_custom_metric');
  return parseFloat(response.data.result[0]?.value[1] || '0');
}
```

## 📞 Поддержка

Для вопросов и предложений создавайте issues в репозитории AetherNova.

## 🏗 Статус разработки

- ✅ Базовая структура и UI
- ✅ Grafana интеграция  
- ✅ Prometheus метрики
- 🔄 Real-time WebSocket обновления
- 🔄 Расширенная система алертов
- 📋 Интеграция с ELK Stack
- 📋 Пользовательские dashboards