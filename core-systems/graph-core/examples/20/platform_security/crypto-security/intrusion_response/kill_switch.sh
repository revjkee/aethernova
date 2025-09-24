#!/bin/bash
# path: platform-security/code-protection/intrusion_response/kill_switch.sh

# TeslaAI Emergency Kill Switch v1.20
# Назначение: мгновенно останавливает CI/CD пайплайны, отключает ключи, закрывает сокеты, уведомляет SecOps

set -euo pipefail

# === Локальный контекст ===
LOGFILE="/var/log/teslaai/kill_switch.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[${TIMESTAMP}] KILL SWITCH ACTIVATED" >> "${LOGFILE}"

# === Отключение CI/CD пайплайнов ===
echo "[${TIMESTAMP}] Terminating CI/CD pipelines..." >> "${LOGFILE}"
systemctl stop gitlab-runner || true
systemctl stop jenkins || true
pkill -9 -f ".git/hooks/post-receive" || true

# === Деактивация ключей (локальных и внешних) ===
echo "[${TIMESTAMP}] Revoking SSH keys..." >> "${LOGFILE}"
grep -v "teslaai-internal" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp
mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys

# GitHub/GitLab API Token revocation (если настроено)
if [ -f "/etc/teslaai/github_tokens.list" ]; then
    while read -r token; do
        curl -s -X DELETE \
            -H "Authorization: token $token" \
            https://api.github.com/applications/<client_id>/token \
            >> "${LOGFILE}" 2>&1 || true
    done < /etc/teslaai/github_tokens.list
fi

# === Блокировка исходящего трафика на 15 минут ===
echo "[${TIMESTAMP}] Blocking outbound traffic..." >> "${LOGFILE}"
iptables -I OUTPUT -j DROP
(sleep 900 && iptables -D OUTPUT -j DROP) &

# === Slack / Email уведомление ===
echo "[${TIMESTAMP}] Notifying SecOps..." >> "${LOGFILE}"
curl -s -X POST \
  -H 'Content-type: application/json' \
  --data "{\"text\":\"KILL SWITCH ACTIVATED. CI/CD pipelines disabled. SSH keys revoked. Time: ${TIMESTAMP}\"}" \
  https://hooks.slack.com/services/TXXXXX/BXXXX/XXXXXXXX || true

echo "[${TIMESTAMP}] Kill switch sequence complete." >> "${LOGFILE}"
