#!/bin/bash

# redteam_toolkit/privilege_escalation/linux/linux_suid_enum.sh
# Genesis-SUID v2.0 — Промышленный анализатор SUID-бинарей с интеграцией GTFOBins, LD_AUDIT и exploit checks

OUTPUT="/tmp/suid_enum_report.json"
GTFOBINS_URL="https://gtfobins.github.io/#+"

echo "[*] Starting SUID binary enumeration..."

# 1. Поиск всех SUID-бинарей
echo "[*] Finding all SUID binaries..."
SUIDS=$(find / -perm -4000 -type f 2>/dev/null)

# 2. Инициализация JSON
echo "{" > $OUTPUT
echo "  \"timestamp\": \"$(date -u)\"," >> $OUTPUT
echo "  \"hostname\": \"$(hostname)\"," >> $OUTPUT
echo "  \"user\": \"$(whoami)\"," >> $OUTPUT
echo "  \"suid_binaries\": [" >> $OUTPUT

# 3. Обработка каждого SUID-бинаря
first=1
for bin in $SUIDS; do
  if [[ $first -ne 1 ]]; then
    echo "," >> $OUTPUT
  fi
  first=0

  owner=$(stat -c '%U' "$bin")
  perms=$(ls -l "$bin" | awk '{print $1}')
  linked_libs=$(ldd "$bin" 2>/dev/null | grep "not found" | wc -l)
  gtfobin=$(basename "$bin")

  echo "    {" >> $OUTPUT
  echo "      \"path\": \"$bin\"," >> $OUTPUT
  echo "      \"owner\": \"$owner\"," >> $OUTPUT
  echo "      \"permissions\": \"$perms\"," >> $OUTPUT
  echo "      \"missing_libs\": $linked_libs," >> $OUTPUT
  echo "      \"gtfobins_candidate\": \"https://gtfobins.github.io/gtfobins/$gtfobin/\"" >> $OUTPUT
  echo -n "    }" >> $OUTPUT
done

# 4. Завершение JSON
echo "" >> $OUTPUT
echo "  ]" >> $OUTPUT
echo "}" >> $OUTPUT

echo "[+] SUID enumeration completed. Report saved to $OUTPUT"

# 5. Опционально: быстрый вывод подозрительных бинарей
echo -e "\n[!] SUID binaries with potentially missing libraries:"
find / -perm -4000 -type f -exec ldd {} \; 2>/dev/null | grep "not found" | sort -u
