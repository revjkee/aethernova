# TeslaAI Genesis RedTeam Toolkit — Tooling Usage Guide

**Версия документа:** 2025.07.25-Genesis  
**Проверка качества:** 20 агентов, 3 метагенерала  
**Описание:** Политики, рекомендации и OPSEC-контроль при использовании инструментов наступательной платформы TeslaAI Genesis в рамках APT-эмуляции, постэксплуатации и lateral movement.

---

## 1. Цель

- Централизовать рекомендации по применению всех встроенных инструментов RedTeam Toolkit.
- Обеспечить соответствие стандартам OPSEC, MITRE ATT&CK и тактической непрослеживаемости.
- Внедрить фазовые правила использования и минимизации цифровых следов.

---

## 2. Классификация Инструментов

| Модуль                 | Тип                   | OPSEC Уровень | MITRE Tactic    |
|------------------------|------------------------|----------------|------------------|
| `sandbox_bypass/`     | Obfuscation/Bypass     | Medium         | Defense Evasion |
| `dns_c2.py`           | C2 Transport           | Low            | Command & Control |
| `host_recon.sh`       | Passive Recon          | Low            | Discovery       |
| `reg_runkey.ps1`      | Persistence Mechanism  | High           | Persistence     |
| `mimikatz_command.txt`| Credential Access Tool | Very High      | Credential Access |

---

## 3. Стандарты Применения

### 3.1 Обход анализа (sandbox_bypass)

- Выполняется **до** любого запуска в среде, где присутствует Defender/EDR.
- Скрипт `check_vm_artifacts.py` активируется автоматически при загрузке shellcode.
- Вариативность sleep delay + timing jitter обязательны.

### 3.2 Beaconing (C2)

- `dns_c2.py` рекомендуется как основной, `http_c2.py` — только с domain fronting.
- Использовать `manager.py` для перезаписи Beacon policy.
- Минимальный тайминг между beacon'ами: 30 минут (ротация IP).

### 3.3 Постэксплуатация (recon, dump)

- `host_recon.sh`: только в режиме stdout→pipe→in-memory.
- `mimikatz_command.txt` можно использовать только через process hollowing в dllhost.exe.
- Удаление всех артефактов сразу после эксфильтрации.

### 3.4 Закрепление (Persistence)

- `reg_runkey.ps1`: выполняется один раз, имеет уникальный хэш-идентификатор (см. GPG sign).
- Проверка записи через `schtasks` не допускается — использовать WMI query.

---

## 4. Уровень Детектируемости

| Tool                     | Detectability | Защита                                      |
|--------------------------|----------------|----------------------------------------------|
| `reg_runkey.ps1`         | HIGH           | Only on obfuscated + AES-encoded mode        |
| `dns_c2.py`              | LOW            | Internal beaconing over cloud fronted domain |
| `mimikatz_command.txt`   | VERY HIGH      | Always use with injection, never as file     |
| `sandbox_bypass/`        | MEDIUM         | Sandboxing Evasion with random seeds         |

---

## 5. Примеры Тактической Интеграции

```yaml
attack_flow:
  - phase: Initial Access
    tools: [sandbox_bypass/check_vm_artifacts.py]
  - phase: Execution
    tools: [dns_c2.py]
  - phase: Persistence
    tools: [reg_runkey.ps1]
  - phase: Credential Access
    tools: [mimikatz_command.txt]
  - phase: Discovery
    tools: [recon/host_recon.sh]
