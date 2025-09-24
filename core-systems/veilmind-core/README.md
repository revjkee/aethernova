# VeilMind Core

Приватность‑ориентированное ядро принятия и выполнения ИИ‑запросов в архитектуре Zero Trust.  
VeilMind обеспечивает минимизацию данных, строгую идентификацию и сегментацию контекста, защиту от утечек (PII/PHI/секреты), проверяемую трассировку и аудируемость решений.

## 1. Ключевые цели

- **Zero‑Data**: обработка по принципу *не собирать, если не нужно*.
- **Deterministic Security**: повторяемая проверка решений, аттестованная временем.
- **Defense‑in‑Depth**: многоуровневые контрмеры (анонимизация → политика → исполнение → аудит).
- **Tamper‑Evident**: хеш‑цепочки аудита, ULID‑метки, HMAC‑подпись артефактов.

## 2. Область применения

- Приватная инференция LLM/NLP/ML с защитой пользовательских и корпоративных данных.
- Политики доступа и трансформации контента, совместимые с Zero‑Trust ядром.
- Интеграция с сетевым периметром (PhantomMesh P2P), SIEM/EDR и системами соответствия.

> Статус: спецификация и контракт интерфейсов для интеграции с `zero-trust-core`. Реализация компонентов в этом репозитории ведущаяся по модульной схеме; используйте контракты ниже при разработке.

---

## 3. Архитектура (обзор)

```mermaid
flowchart LR
  C[Client/App] --> GW[Zero-Trust Gateway]
  GW -->|context+policy| PM[Policy Engine (zero-trust-core)]
  PM -->|decision| VM[VeilMind Runtime]
  VM -->|sanitize/PII redact| AN[Anonymizer Pipeline]
  VM -->|allowed| EX[Model Executor]
  VM -->|deny/obligations| BL[Block/Transform]
  VM --> AU[Audit Chain]
  subgraph Zero-Trust Core
    PM
    AU
  end
