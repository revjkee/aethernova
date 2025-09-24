# Базовый образ с поддержкой PostgreSQL, Zabbix frontend, server, agent и SNMP
FROM zabbix/zabbix-appliance:6.4-latest

LABEL maintainer="TeslaAI Genesis Monitoring Core"
LABEL version="6.4.2"
LABEL description="Промышленный Zabbix сервер с поддержкой AI-интеграций и Prometheus"

# Установка необходимых инструментов и зависимостей
USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        jq \
        vim \
        net-tools \
        iputils-ping \
        zabbix-get \
        zabbix-sender \
        gnupg \
        ca-certificates \
        python3 \
        python3-pip \
        supervisor && \
    rm -rf /var/lib/apt/lists/*

# Установка Python-расширений для интеграции с AI-агентами и Prometheus Push Gateway
RUN pip3 install --no-cache-dir \
    requests \
    prometheus_client \
    zabbix-api \
    pyzabbix \
    numpy \
    pandas

# Конфигурация переменных окружения
ENV ZBX_SERVER_NAME="TeslaAI Zabbix Node"
ENV ZBX_TIMEOUT=30
ENV ZBX_LOGLEVEL=3
ENV PHP_TZ=UTC

# Копирование пользовательских скриптов и шаблонов
COPY ./conf/zabbix_custom_templates.xml /etc/zabbix/templates/
COPY ./scripts/ai_integration.py /opt/zabbix/scripts/
COPY ./supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Открытие необходимых портов
EXPOSE 80 10051 10050

# Настройка прав
RUN chmod +x /opt/zabbix/scripts/ai_integration.py

# Точка входа через Supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
