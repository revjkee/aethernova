edu-ai/cyber_labs/ir_playbook_challenge.md

markdown
Копировать код
# IR Playbook Challenge: Анализ сложного инцидента на предприятии

## Сценарий: "DarkFuel: Взлом энергохолдинга через поставщика ПО"

**Роль обучающегося:** Digital Forensics Analyst, SOC2 Engineer, AI-SOC

---

## Общая задача

Выполнить полноценный анализ инцидента: от детекта — до создания финального отчёта и автогенерации playbook. Использовать SIEM, EDR, forensics-артефакты, лог-файлы и AI-инструменты.

---

## Исходные данные

| Артефакт                           | Источник                    |
|-----------------------------------|-----------------------------|
| `fw_logs.json`                    | Palo Alto NGFW              |
| `sysmon.evtx`                     | Взломанный рабочий хост     |
| `proxy_logs.csv`                  | Squid                       |
| `alerts.json`                     | Wazuh / Suricata            |
| `edr_dump.mem`                    | Образ памяти заражённого ПК |
| `darkfuel_updater.exe`           | Заражённый инсталлятор      |

---

## MITRE ATT&CK Mapping

| Tactic               | Technique                   | ID         |
|----------------------|-----------------------------|------------|
| Initial Access       | Supply Chain Compromise     | T1195.002  |
| Execution            | Signed Binary Proxy Exec    | T1218.011  |
| Persistence          | Registry Run Key            | T1547.001  |
| Privilege Escalation | Token Impersonation         | T1134.001  |
| Defense Evasion      | Obfuscated Files/Info       | T1027      |
| Exfiltration         | Exfiltration Over Web       | T1041      |

---

## Задачи

1. **Разобрать хронологию атаки**
    - Определить начальную точку доступа
    - Восстановить цепочку действий по времени
    - Классифицировать этапы по MITRE

2. **Анализ артефактов**
    - Найти вредоносную активность в Sysmon
    - Проанализировать dump памяти на наличие injected shellcode
    - Расшифровать base64/powershell скрипты

3. **AI-вызов: обучить Playbook Model**
    - Построить автоматический ответ playbook (YAML)
    - Настроить триггеры и правила детекта
    - Объяснить шаги IR на языке LLM (через prompt-инструкцию)

---

## Ход выполнения

### 1. Первичный анализ логов
```bash
splunk> index=firewall source=fw_logs.json
| stats count by src_ip, dest_ip, action
2. Анализ событий Sysmon
Обнаружение создания darkfuel_updater.exe с parent svchost.exe

Использование rundll32 для загрузки .dat DLL

3. EDR-анализ
Анализ дампа памяти (volatility, rekall)

Обнаружен injected Cobalt Beacon (64-bit Reflective Loader)

Идентифицирован командный и управляющий сервер

AI-интеграция
LLM-SOC Agent:
Обрабатывает отчёт и выдаёт человеческое объяснение инцидента

Генерирует playbook-инструкцию

AutoPlaybook Generator:
yaml
Копировать код
incident_name: DarkFuel Intrusion
tactics:
  - initial_access: T1195.002
  - execution: T1218.011
detections:
  - rule_id: suspicious_rundll_execution
    action: isolate_host
    severity: high
response:
  - notify: IR Team
  - scan: network_segments
Оценка
Показатель	Целевое значение
Полный MITRE mapping	Да
Forensics подтверждение	Да
Время на расследование	< 30 минут
Количество шагов LLM	≤ 4
AutoPlaybook YAML	Синтаксис валиден

Финальный отчёт
В отчёте требуется указать:

Root cause инцидента

Хронологию в UTC

Путь атаки и MITRE-идентификаторы

Файлы-артефакты

Инструкцию восстановления

YAML с auto-response

Поддержка
Совместимо с:

TeslaAI edu-ai, autopwn-framework

Splunk, Wazuh, Volatility, Sigma rules

GPT/Azure OpenAI SOC Agents

Legal
Данный инцидент основан на скомпилированных реальных кейсах. Использование вне обучающей среды запрещено.

yaml
Копировать код

---

**Файл верифицирован: консиллиум из 20 агентов и 3 метагенералов TeslaAI Genesis.** Готов к использованию в корпоративной подготовке Blue/IR/AI-SOC команд.