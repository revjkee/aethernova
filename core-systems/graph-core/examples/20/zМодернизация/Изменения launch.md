launch/
├── bootstrap/
│   ├── preflight_checklist.yaml   !     # VPN, порты, зависимости
│   ├── bootstrap_ai_core.py       !     # Запуск AI ядра
│   ├── bootstrap_bot.py           !     # Telegram бот
│   ├── bootstrap_webapp.sh        !     # Web-интерфейс
│   ├── bootstrap_worker.py        !     # Очереди/потоки
│   └── bootstrap_graph_core.py    !     # Инициализация knowledge graph

├── recovery/
│   ├── fail_injection.yaml        !     # Симуляция катастроф и откатов
│   ├── disaster_recovery_plan.md  !     # Пошаговый план DR
│   ├── snapshot_restore.sh      !       # Восстановление из snapshot
│   └── integrity_verifier.py      !     # Проверка хэшей и подписи

├── self_state/
│   ├── ai_state_log.json        !       # Статусы всех агентов и подсистем
│   ├── launch_telemetry.log    !        # Метрики первого запуска
│   └── inhibitors_checkpoint.yaml   !   # self-inhibitor → флаги ошибок

├── migrations/
│   ├── run_migrations.sh  !
│   ├── alembic_upgrade.log  !
│   └── vault_unseal_tracker.json  !

├── deploy/
│   ├── docker_compose_launch.yml  !
│   ├── launch_k8s_profile.yaml  !
│   ├── web3_signer_init.py  !
│   └── signature_verifier.py     !      # Подписи компонентов

├── env_profiles/
│   ├── local.env  !
│   ├── staging.env !
│   ├── production.env  !
│   ├── airgap.env  !
│   └── ephemeral_test.env     !          # Временное окружение для CI или фичей

├── diagnostics/
│   ├── system_report.md  !
│   ├── error_dump.log!
│   ├── ai_healthcheck.py!
│   └── version_sync_checker.py   !      # Проверка соответствия версий

├── launch_flags/
│   ├── genesis_mode.flag!
│   ├── fail_safe_mode.flag!
│   ├── debug_mode.flag!
│   └── ethics_lock.flag       !         # Блокировка запуска без этического контроля

├── approvals/
│   ├── launch_signatures/!
│   │   ├── launch.pub!
│   │   └── launch.sig!
│   └── signoff_policy.yaml      !      # Кто имеет право запускать платформу

├── versioning/
│   ├── version_manifest.yaml!
│   ├── upgrade_notices.md!
│   └── rollback_points.json!

└── README.md
