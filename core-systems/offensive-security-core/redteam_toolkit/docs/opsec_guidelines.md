# TeslaAI Genesis RedTeam Toolkit — OPSEC Guidelines

**Версия документа:** 2025.07.25-Genesis  
**Верификация:** 20 агентов, 3 метагенерала  
**Цель:** Обеспечение полной скрытности и неотслеживаемости во время проведения наступательных операций, включая APT-эмуляции, постэксплуатацию и C2.

---

## 1. OPSEC Роли и Ответственность

| Уровень         | Описание                                | Контроль                                 |
|----------------|------------------------------------------|-------------------------------------------|
| Operator       | Выполнение процедур                       | Следует только документированным шагам   |
| OPSEC Officer  | Анализ каналов утечек, включение/отключение логгирования | Обязателен для фаз Beaconing, C2, Pivoting |
| C2 Architect   | Контроль над маршрутизацией и доменами    | Использование jitter и доменных фронтов  |

---

## 2. Основные Принципы

- **Zero-trust к любым endpoint-данным.**
- **Изоляция артефактов (инъекторы, стейджеры) по стадии.**
- **Логгирование должно быть либо выключено, либо перенаправлено.**
- **Любой код должен быть polymorphic, obfuscated или packed.**
- **Контроль таймингов, jitter, и random sleep обязателен.**

---

## 3. OPSEC По Этапам

### 3.1 Reconnaissance

- Использовать **passive recon** (например, ASN, MX, Certificate Transparency).
- Заблокировать DNS-resolve с live-инфраструктуры.
- Использовать обфускацию при любых WHOIS-запросах.

### 3.2 Initial Access

- Фишинг-письма должны быть вручную написаны, не сгенерированы LLM.
- Использование **burner доменов** через CDN (CloudFront, Fastly).
- Payload — без PE/EXE (через LNK, HTA, ISO, OneNote exploit).

### 3.3 Execution

- Применять **parent PID spoofing**.
- Удаление скриптов после drop.
- Использовать PowerShell в **In-Memory only режиме**.

### 3.4 Persistence

- Применять `reg_runkey.ps1` с уникальным хэшем скрипта.
- Не использовать одинаковые имена задач или ключей.

### 3.5 Privilege Escalation

- Отключить stdout/stderr логгирование (например, при использовании Juicy Potato).
- Удаление временных DLL после использования.

### 3.6 C2 & Lateral Movement

- Использовать C2 с поддержкой Domain Fronting (`http_c2.py`, `mqtt_c2.py`, `dns_c2.py`).
- Активировать sleep + jitter (15m–2h случайно).
- Распределять beacon-тайминги через decoy-трафик.

---

## 4. Артефакты и Управление ими

| Артефакт                | OPSEC-рекомендация                    |
|-------------------------|----------------------------------------|
| Payload (EXE/DLL)       | Только с polymorphic encryptor, self-delete |
| Scripts (PS1, SH)       | Шифрование и удаление после exec        |
| Registry Keys           | Уникальные, скрытые под системные      |
| C2 Channels             | DNS+HTTP fallback, proxy-chaining      |

---

## 5. Детектируемость (Detectability Rating)

| Компонент                 | RISK | Флаг Detectable |
|--------------------------|------|-----------------|
| evasion/aes_encryptor.py | Low  | No              |
| post_exploit/reg_runkey  | High | Yes             |
| http_c2.py               | Medium | Yes (если без Fronting) |
| dns_c2.py                | Low  | No              |
| sandbox_bypass           | Medium | No              |

---

## 6. Стратегии Защиты От Blue Team

- Использование **IAT Hooking** вместо API injection.
- Чередование прокси-цепочек TOR+VPN+Custom obfs.
- Логгировать телеметрию на стороне атакующего, не в памяти агента.
- Использовать псевдокоманды при Beacon Response (decoys).
- Шифрование внутри C2 payload — минимум AES-256-GCM.

---

## 7. Встроенные Checks

- `check_vm_artifacts.py` → выполняется до каждого действия.
- `sandbox_bypass/ping_response_timing.py` → базовый тайминг-анализ.
- `latency_tracker.py` из `logging/latency/` подключён к каждой фазе exec.

---

## 8. Валидация и Контроль

```json
{
  "version": "1.0.2025-industrial",
  "verified_by": {
    "agents": 20,
    "metagenerals": 3
  },
  "hash": "9fd3c1c81db59a421b3a3ec991b4cfaae70f67bd77543e4087d16d7de52eecdd"
}
