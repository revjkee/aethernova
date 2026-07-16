#!/bin/bash
# Скрипт для настройки базового firewall на Kubernetes узлах
# Цель: минимизировать доступ по умолчанию, разрешить только необходимые порты и протоколы

set -euo pipefail

# Настройка переменных
ALLOWED_SSH_PORT=22
K8S_API_SERVER_PORT=6443
NODE_EXPORTER_PORT=9100
CALICO_ETCD_PORT=2379-2380
KUBELET_PORT=10250

# Функция для очистки текущих правил iptables
flush_rules() {
    echo "Очистка текущих правил iptables..."
    iptables -F
    iptables -X
    iptables -Z
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
}

# Разрешить loopback и установленные соединения
allow_loopback_and_established() {
    echo "Разрешение loopback и установленных соединений..."
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

# Разрешить SSH доступ
allow_ssh() {
    echo "Разрешение SSH порта ${ALLOWED_SSH_PORT}..."
    iptables -A INPUT -p tcp --dport ${ALLOWED_SSH_PORT} -j ACCEPT
}

# Разрешить Kubernetes API Server доступ
allow_k8s_api_server() {
    echo "Разрешение порта Kubernetes API Server ${K8S_API_SERVER_PORT}..."
    iptables -A INPUT -p tcp --dport ${K8S_API_SERVER_PORT} -j ACCEPT
}

# Разрешить Kubelet
allow_kubelet() {
    echo "Разрешение Kubelet порта ${KUBELET_PORT}..."
    iptables -A INPUT -p tcp --dport ${KUBELET_PORT} -j ACCEPT
}

# Разрешить Node Exporter (мониторинг)
allow_node_exporter() {
    echo "Разрешение Node Exporter порта ${NODE_EXPORTER_PORT}..."
    iptables -A INPUT -p tcp --dport ${NODE_EXPORTER_PORT} -j ACCEPT
}

# Разрешить Calico etcd (если используется)
allow_calico_etcd() {
    echo "Разрешение Calico etcd портов ${CALICO_ETCD_PORT}..."
    iptables -A INPUT -p tcp -m multiport --dports ${CALICO_ETCD_PORT} -j ACCEPT
}

# Логирование и отклонение остального
final_rules() {
    echo "Добавление правил логирования и отклонения..."
    iptables -A INPUT -j LOG --log-prefix "iptables denied: " --log-level 4
    iptables -A INPUT -j DROP
}

main() {
    flush_rules
    allow_loopback_and_established
    allow_ssh
    allow_k8s_api_server
    allow_kubelet
    allow_node_exporter
    allow_calico_etcd
    final_rules

    echo "Firewall настроен успешно."
}

main "$@"
