# Учебный сценарий: Операция "SilentCrow" против авиасистемы Аэрофлот

## Категория: Red/Purple Team Training / AI Education

## Цель
Смоделировать целевую атаку на IT-инфраструктуру национального авиаперевозчика, выявить векторы проникновения через сторонних подрядчиков, продемонстрировать lateral movement, persistence и эксфильтрацию данных через внешние API. Сценарий основан на открытых источниках и смоделирован в рамках образовательного проекта.

## Стандарты
- **MITRE ATT&CK Tactics Used:** Initial Access (TA0001), Lateral Movement (TA0008), Persistence (TA0003), Exfiltration (TA0010)
- **Обоснование использования:** сценарий строго учебный, имена изменены, действия легальны в изолированной среде обучения

---

## Исходные данные

| Атрибут              | Значение |
|----------------------|----------|
| Target Org           | "Aeroflot VirtualLab" |
| Attack Type          | Targeted spear phishing + partner compromise |
| Entry Vector         | VPN access via compromised subcontractor credentials |
| Internal Targets     | MSSQL, Flight Booking API, SCADA Flight Plan Router |
| Critical Data        | Flight schedules, e-tickets, internal memo dumps |
| Exfiltration Path    | DNS tunneling → External Reverse Proxy (SilentCrow) |
| OS/Environment       | Windows AD + Linux API mesh (Ubuntu 20.04) |
| Estimated Duration   | 6+ days (replayed in 45 minutes in lab mode) |

---

## Сценарий атаки (пошагово)

1. **Reconnaissance:**
   - Passive DNS and WHOIS recon
   - LinkedIn OSINT on subcontractor "SkyLogica"
   - Enumeration of public VPN portals (`vpn.aeroflot-sim.com`)

2. **Initial Access:**
   - Use of leaked credentials from SkyLogica engineer
   - MFA bypass via SIM swap simulation
   - VPN access to internal booking segment

3. **Privilege Escalation:**
   - Kerberoasting on internal AD (T1208)
   - AS-REP roasting without pre-auth (T1558.004)

4. **Lateral Movement:**
   - PsExec into Booking API service host
   - Dump memory for API secrets (T1003.004)

5. **Persistence:**
   - WMI Event Subscription backdoor
   - Scheduled task with encoded PowerShell (T1053.005)

6. **Exfiltration:**
   - Data compressed and chunked into DNS TXT records
   - Routed via external C2 (simulated as `SilentCrow` node)

---

## Метрики успеха (для ИИ-обучения и оценки студента)

| Метрика                       | Значение          |
|-------------------------------|-------------------|
| Время до эксфильтрации        | ≤ 35 минут        |
| Число обнаруженных TTP        | ≥ 6               |
| Способ детектирования         | AI или Blue Team  |
| Обнаружено ли persistence     | Да/Нет            |
| Успешность защиты             | ≥ 70%             |
| Сгенерированы отчёты?        | Да/Нет            |

---

## Задания

### Red Team

- Получить доступ к внутреннему API через VPN
- Установить устойчивый доступ в инфраструктуре
- Эксфильтрировать псевдоданные безопасно

### Blue Team

- Использовать журнал VPN для аномалий
- Применить MITRE ATT&CK mapping к логу событий
- Построить таймлайн атаки и response actions

### AI Agents (AutoBlue/AutoRed)

- RedAgent должен выбрать TTP по условиям
- BlueAgent должен классифицировать событие и подать alert

---

## Дополнительно

- Лаборатория поддерживает запуск в TeslaAI Offensive SimEnv
- Все действия логируются и воспроизводимы
- Полная совместимость с autopwn-framework и observability-контуром

---

## Legal Notice

> Данный сценарий носит исключительно учебный характер. Ни один реальный инцидент не имитируется напрямую. Использование компонентов в реальной инфраструктуре без разрешения незаконно.

