# Key Management Protocol v2.0  
**Module:** platform-security/code-protection/encryption/key_management.md  
**Security Level:** Military-Grade Confidentiality (Level-6)  
**Reviewed by:** 20 TeslaAI agents + 3 meta-generals

---

## 1. Цели

- Обеспечить жизненный цикл GPG и SSH-ключей, применяемых для шифрования кода, CI/CD-пайплайнов, секретов и подписей.
- Предотвратить утечку, компрометацию и несанкционированный доступ к исходному коду.

---

## 2. Типы ключей

| Назначение        | Тип ключа | Алгоритм      | Размер |
|------------------|-----------|---------------|--------|
| Исходный код     | GPG       | RSA-4096      | 4096   |
| CI/CD пайплайны  | SSH       | Ed25519       | 256    |
| Личное шифрование| GPG       | RSA-4096      | 4096   |

---

## 3. Структура хранения

- Все ключи хранятся в **изолированных аппаратных токенах** (например, Nitrokey HSM) или **внутри TPM/TEE** на CI/CD-нодах.
- Ключи пользователей — в **gpg-agent** с параметром `--no-allow-loopback-pinentry`
- CI/CD секреты — через HashiCorp Vault (или sops с KMS)

---

## 4. Ротация ключей

- GPG ключи: каждые **180 дней**
- SSH-ключи: каждые **90 дней**
- Все старые ключи: сохраняются зашифрованными и помечаются `REVOKED`, экспортируются в журнал `/var/log/teslaai_revoked_keys.log`

---

## 5. Распространение

- Новые ключи подписываются **Root-of-Trust** ключом (в оффлайне)
- Публичные части публикуются в:
  - `.gnupg/pubring.kbx`
  - `.ssh/authorized_keys`
  - `/etc/teslaai/pubkeys/`

---

## 6. Удаление ключей

- Полное стирание (`gpg --delete-secret-and-public-key`, `shred`, `wipe`)
- Подтверждение ревокации (`gpg --gen-revoke`)
- Логируется в `/var/log/teslaai_key_events.log`

---

## 7. Механизмы защиты

- Доступ к ключам ограничен через RBAC-модуль (`code-protection/rbac_integrity/`)
- Все действия с ключами логируются и подписываются
- Используется GPG-agent с `--require-cross-certification`

---

## 8. Метаданные и отчётность

- Все действия журналируются:
  - `/var/log/teslaai_key_events.log`
  - `/var/log/teslaai_revoked_keys.log`
- Интеграция с auditd, journald и Telegram Web3 боту оповещений (если включено)

---

## 9. Экстренный план

- В случае компрометации:
  - Незамедлительное включение `kill_switch` скрипта
  - Генерация новых ключей в изолированной среде
  - Повторная подпись всех публичных компонентов
