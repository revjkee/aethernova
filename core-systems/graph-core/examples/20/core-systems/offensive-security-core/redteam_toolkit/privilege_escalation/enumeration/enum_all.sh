#!/bin/bash

# redteam_toolkit/privilege_escalation/enumeration/enum_all.sh
# Genesis-Enum v3.0 — промышленный скрипт сбора LPE-индикаторов, анализ прав, конфигураций, контейнеризации и сетей

OUTFILE="/tmp/enum_all_$(hostname)_$(date +%s).json"
TMPDIR="/tmp/enumscan"
mkdir -p "$TMPDIR"

write_json_section() {
  SECTION="$1"
  CMD="$2"
  echo "  \"$SECTION\": [" >> "$OUTFILE"
  $CMD | sed 's/"/\\"/g' | sed 's/^/    "/;s/$/",/' >> "$OUTFILE"
  echo "  ]," >> "$OUTFILE"
}

echo "{" > "$OUTFILE"
echo "  \"host\": \"$(hostname)\"," >> "$OUTFILE"
echo "  \"datetime\": \"$(date -u)\"," >> "$OUTFILE"

# 1. User info
write_json_section "user_info" "id; whoami; groups"

# 2. Kernel and distro
write_json_section "kernel" "uname -a"
write_json_section "distro" "cat /etc/*release 2>/dev/null"

# 3. Running processes
write_json_section "processes" "ps aux --sort=-%mem | head -n 30"

# 4. Network info
write_json_section "network_interfaces" "ip a"
write_json_section "netstat_open_ports" "netstat -tulpen 2>/dev/null || ss -tulpen"

# 5. Cron jobs
write_json_section "cron_jobs" "for u in \$(cut -f1 -d: /etc/passwd); do crontab -l -u \$u 2>/dev/null; done"
write_json_section "system_cron" "cat /etc/crontab /etc/cron.*/* 2>/dev/null"

# 6. SUID binaries
write_json_section "suid_binaries" "find / -perm -4000 -type f 2>/dev/null"

# 7. Capabilities
write_json_section "capabilities" "getcap -r / 2>/dev/null"

# 8. Docker / LXC detection
write_json_section "container_check" "grep -qa 'docker\|lxc' /proc/1/cgroup && echo 'Container detected' || echo 'Not in container'"

# 9. Weak permissions
write_json_section "writable_etc" "find /etc -writable -type f 2>/dev/null"
write_json_section "writable_shadow" "ls -la /etc/shadow 2>/dev/null"

# 10. SSH keys
write_json_section "ssh_keys" "find / -name 'id_rsa' -o -name 'authorized_keys' 2>/dev/null"

# 11. Journald recent logs
write_json_section "journald_logs" "journalctl -xe -n 100 2>/dev/null"

# 12. Kernel exploits hint
write_json_section "kernel_exploits" "uname -r | xargs -I{} curl -s 'https://www.linuxkernelcves.com/?search={}' | grep -A2 'exploit-db' || echo 'Offline lookup required'"

# 13. Miscellaneous
write_json_section "mounts" "mount"
write_json_section "fstab" "cat /etc/fstab"
write_json_section "sudoers" "cat /etc/sudoers 2>/dev/null"

# 14. Environment
write_json_section "env_variables" "env"

# Final
echo "  \"complete\": true" >> "$OUTFILE"
echo "}" >> "$OUTFILE"

echo "[+] Recon complete. Output saved to: $OUTFILE"
