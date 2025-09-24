# intel-core/correlation-engine/rules/anomaly_rules.dsl

# Правила аномалий для корреляционного движка

rule "Unusual Login Times" {
    description: "Обнаружение логинов вне рабочего времени"
    event_type: "login"
    condition: event.timestamp.hour < 8 or event.timestamp.hour > 20
    threshold: 3
    time_window: 86400  # 24 часа в секундах
    action: alert("Medium")
}

rule "Data Exfiltration Spike" {
    description: "Всплеск передачи данных за короткий период"
    event_type: "data_transfer"
    condition: event.volume > 500000000 and event.count > 10
    time_window: 3600  # 1 час
    action: alert("High")
    action: notify("security_team")
}

rule "Multiple Failed Authentications" {
    description: "Многочисленные неудачные попытки аутентификации"
    event_type: "auth_failure"
    condition: event.count >= 5
    time_window: 300  # 5 минут
    action: alert("High")
    action: block(event.source_ip)
}

rule "New User-Agent Detected" {
    description: "Обнаружение нового user-agent"
    event_type: "http_request"
    condition: not database.contains(event.user_agent)
    action: alert("Low")
    action: log(event)
}

rule "Rare IP Access" {
    description: "Доступ с редких IP-адресов"
    event_type: "network_access"
    condition: not database.ip_whitelist.contains(event.source_ip)
    threshold: 1
    action: alert("Medium")
}

