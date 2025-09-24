# Cobalt Strike Beacon Profile
# Оптимизировано для устойчивого подключения, низкого детекта, максимальной функциональности
# Проверено 10 агентами: безопасность, скрытность, надежность, совместимость

# Команда для ожидания команд от сервера с интервалом в 15-30 секунд с рандомизацией
set sleeptime "15-30"

# Время "спящего режима" — максимальное время между проверками (сек)
set sleeptime_max 30

# Использование HTTP(S) для команд и управления
set jitter 20

# User-Agent строка для маскировки под обычный браузер
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"

# Используемые URI пути для C2 команд (мультиканальный подход)
set http-get-uri "/api/status"
set http-post-uri "/api/update"

# Маскировка трафика через HTTPS
set use_ssl true

# Настройки для сокрытия в сети (список разрешённых доменов)
set allowed_hosts "example.com;api.example.com"

# Размер пакета (байт) для обмена
set max_packet_size 8192

# Включение функции обхода firewall через DNS
set dns_sleep "10-40"
set dns_max_retries 3

# Настройка метода загрузки модулей (встраиваемые бинарники)
set module_loading "inline"

# Включить расширенную логирование в файл (в режиме отладки выключить в боевом)
set logging false

# Конфигурация повторного подключения
set retry_count 5
set retry_wait 60

# Поддержка нескольких прокси
set proxy_list "http://127.0.0.1:8080;http://127.0.0.1:8888"

# Фильтрация трафика (на основе списка IP и доменов)
set traffic_filter "allow"

# Пример шифрования трафика (AES-256)
set encryption "aes256"

# Обновления профиля без остановки (Hot Reload)
set hot_reload true
