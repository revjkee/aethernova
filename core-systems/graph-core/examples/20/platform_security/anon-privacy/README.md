# anon-core — Модуль цифровой анонимности и укрытия  
**Проект TeslaAI Genesis / platform-security/anon-core/**  
Версия: Genesis v7.4 | Уровень допуска: CLASS-ZERO-LEAK

---

## Назначение

`anon-core` — это центральный модуль цифрового укрытия и анонимной операционной инфраструктуры. Он обеспечивает:
- Полную обфускацию личности, сетевого следа и поведения
- Многоуровневую ротацию MAC/IP/Fingerprint/GPG/Persona
- Протоколирование всех событий ротации, утечек, загрузок и сетевых взаимодействий
- Интеграцию с Tor, WireGuard, DNSCrypt, hardened-VM и Zero-Trust агентами

---

## Архитектура

sql
Копировать
Редактировать
             [ USER SPACE ]
                    |
 +------------------+------------------+
 |     Identity     |     Routing      |
 |   Management     |     Control      |
 | pseudonym_agent  |  wg+tor_bridge   |
 +------------------+------------------+
        |                     |
 +------+-------+     +------+--------+
 |  Fingerprint |     |   DNS & Leak  |
 |  Simulator   |     |   Detection   |
 +--------------+     +---------------+

            [ AGENT CORE + LOGS ]
markdown
Копировать
Редактировать

---

## Ключевые компоненты

### Поведенческая защита (`/behavior`)
- `pseudonym_manager.py` — генерация личностей
- `identity_rotation.sh` — синхронная смена всех слоёв
- `mat2_wrapper.py` — очистка метаданных
- `startup_guard.sh` — форензическая проверка при старте

### Коммуникация (`/communications`)
- `onion_hosting_setup.sh` — скрытый сервис
- `file_drop_server.py` — однократный onion-файлшаринг

### Агенты (`/agents`)
- `log_cleaner.sh` — безопасная ротация логов
- `fingerprint_monitor.py` — монитор отпечатков
- `startup_guard.sh` — обнаружение виртуализации и утечек

### Конфигурации (`/configs`)
- `wg_template.conf` — эталон WireGuard
- `dnscrypt_template.toml` — приватный DNS-клиент
- `tor_ports.list` — унифицированный список портов

### Логи (`/logs`)
- `ip_check.log` — мониторинг публичного IP
- `dns_leak.log` — перехваченные DNS-утечки
- `rotation_history.log` — история смен идентичности

---

## Принципы

- **Zero Trust**: каждый элемент проверяется на каждом шаге
- **OneShot Identity**: каждая сессия — уникальна, невосстановима
- **No Logs by Design**: логи только внутри защищённой зоны, с очисткой
- **Layered Rotation**: псевдоним, MAC, IP, fingerprint, ключи — смена в одну транзакцию
- **Kill Switch**: автоматическое выключение при утечке

---

## Интеграция

Модуль интегрируется с:
- `platform-security/code-protection/`
- `offensive-security/autopwn-framework/`
- `monitoring/log-bridge/`
- `AI-platform-core/guard-agents/`

---

## Допуски

Данный модуль допускается к запуску только в рамках:
- Hardened VM
- Nested TUN внутри wg+tor
- Заблокированного clearnet доступа
- DNS-over-Tor с фильтрацией

---

## Подпись

Разработано в рамках  
**TeslaAI Genesis Platform-Security Division**  
Проверено: 20 агентов, 3 генерала  
Контроль: AI-Jailkeeper, Zero-Leak Auditor
