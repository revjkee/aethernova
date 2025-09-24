---
schemaVersion: "1.0.0"
templateVersion: "2025-08-25"
documentType: "evidence-report"

evidence:
  id: "{{EVIDENCE_ID}}"
  name: "{{EVIDENCE_NAME}}"
  category: "{{CATEGORY}}"        # Security | Reliability | Change | Data | Vendor
  controls:
    - "{{CONTROL_1}}"             # пример: SOC2-CC7.2
    - "{{CONTROL_2}}"             # пример: ISO27001-A.12.4
  environment: "{{ENVIRONMENT}}"  # prod | staging | dev
  project: "oblivionvault-core"
  owner: "Platform-Security & SRE"
  classification: "{{CLASSIFICATION}}"  # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
  retentionDays: {{RETENTION_DAYS}}
  worm: {{WORM_BOOL}}             # true | false
  slaMinutes: {{SLA_MINUTES}}     # например 60
  runbook: "{{RUNBOOK_PATH}}"     # относительный путь в каталоге runbooks
  dashboards:
    grafanaBaseURL: "{{GRAFANA_BASE_URL}}"
    uids: ["{{DASHBOARD_UID_1}}","{{DASHBOARD_UID_2}}"]

integrity:
  hashAlgorithm: "{{HASH_ALGO}}"  # sha3-512 по умолчанию
  digest: "{{DIGEST}}"            # итоговый хеш бандла или основного артефакта
  cosign:
    enabled: {{COSIGN_ENABLED}}   # true | false
    signature: "{{COSIGN_SIG}}"
    keyRef: "{{COSIGN_KEYREF}}"   # awskms:///alias/ovc-cosign
    rekorUUID: "{{REKOR_UUID}}"
  gpg:
    enabled: {{GPG_ENABLED}}      # true | false
    signature: "{{GPG_SIG}}"
    keyId: "{{GPG_KEYID}}"
  inToto:
    enabled: {{INTOTO_ENABLED}}   # true | false
    subject: "{{INTOTO_SUBJECT}}" # hash или предметная ссылка in-toto

storage:
  primaryS3Uri: "{{S3_URI}}"              # s3://ovc-evidence-.../staging/...
  secondaryS3Uri: "{{S3_DR_URI}}"         # s3://ovc-evidence-dr/... (опционально)
  kmsKeyArn: "{{KMS_ARN}}"
  objectLock:
    mode: "{{LOCK_MODE}}"                 # GOVERNANCE | COMPLIANCE
    retentionUntil: "{{LOCK_UNTIL_ISO8601}}"

collection:
  collectorRef: "{{COLLECTOR_REF}}"       # ссылка на collectors из evidence.yaml
  schedule: "{{SCHEDULE}}"                # cron(...) или rate(...)
  deliveredAt: "{{DELIVERED_AT_ISO8601}}"
  sourceEndpoints:
    - "{{SOURCE_ENDPOINT_1}}"
    - "{{SOURCE_ENDPOINT_2}}"
  queryRef: "{{QUERY_OR_CMD}}"            # PromQL, CLI, API-метод

approvalsWorkflow: "{{WORKFLOW_ID}}"      # WF-SEC-CRITICAL | WF-STANDARD
---

# 1. Краткое резюме
Цель: кратко объяснить, какое доказательство предоставляется, зачем оно нужно и какое требование закрывает.

- Что: {{EVIDENCE_NAME}}
- Зачем: закрывает требования контролей {{CONTROL_1}}, {{CONTROL_2}}
- Когда: собран {{DELIVERED_AT_ISO8601}} по расписанию {{SCHEDULE}}
- Ответственные: {{OWNER_NAME_OR_ROLE}}
- SLA: {{SLA_MINUTES}} минут с момента события до публикации

# 2. Инвентаризация артефактов
Ниже перечислены первичные и дополнительные артефакты, включенные в пакет доказательств.

| Артефакт | URI | Размер | Хеш ({{HASH_ALGO}}) | Подпись | Классификация |
|---|---|---:|---|---|---|
| {{ARTIFACT_NAME_1}} | {{ARTIFACT_URI_1}} | {{ARTIFACT_SIZE_1}} | {{ARTIFACT_DIGEST_1}} | {{ARTIFACT_SIG_1}} | {{CLASSIFICATION}} |
| {{ARTIFACT_NAME_2}} | {{ARTIFACT_URI_2}} | {{ARTIFACT_SIZE_2}} | {{ARTIFACT_DIGEST_2}} | {{ARTIFACT_SIG_2}} | {{CLASSIFICATION}} |

Примечание: полный список вложен в файл manifest.json внутри пакета.

# 3. Соответствие контролям
Сопоставление артефактов и выводов с контролями.

| Контроль | Описание (кратко) | Обоснование соответствия | Ссылки на артефакты |
|---|---|---|---|
| {{CONTROL_1}} | {{CONTROL_1_DESC}} | {{RATIONALE_1}} | {{ARTIFACT_LINKS_1}} |
| {{CONTROL_2}} | {{CONTROL_2_DESC}} | {{RATIONALE_2}} | {{ARTIFACT_LINKS_2}} |

# 4. Цепочка владения (Chain of Custody)
Хронология операций над артефактами от сбора до публикации.

| Timestamps (UTC) | Действие | Субъект | Артефакт | Реквизиты |
|---|---|---|---|---|
| {{TS1}} | Сбор | {{ACTOR1}} | {{ARTIFACT_NAME_1}} | source={{SOURCE_ENDPOINT_1}} |
| {{TS2}} | Подпись | {{ACTOR2}} | {{ARTIFACT_NAME_1}} | cosign={{COSIGN_SIG}} |
| {{TS3}} | Нотариат | {{ACTOR3}} | {{ARTIFACT_NAME_1}} | rekorUUID={{REKOR_UUID}} |
| {{TS4}} | Публикация | {{ACTOR4}} | пакет | s3={{S3_URI}} |

# 5. Проверка целостности и подлинности
Команды и процедуры для верификации артефактов.

```bash
# Проверка хеша
sha3sum -c manifest.sha3   # или sha256sum для SBOM

# Проверка cosign-подписи
cosign verify --key {{COSIGN_KEYREF}} {{ARTIFACT_URI_1}}

# Проверка в журнале прозрачности Rekor
rekor-cli get --uuid {{REKOR_UUID}}

# Проверка GPG-подписи (если включена)
gpg --verify {{GPG_SIG}} {{ARTIFACT_NAME_1}}

# Проверка in-toto (если включена)
in-toto-verify --layout supplychain/in-toto.layout.json --layout-keys owner.pub
