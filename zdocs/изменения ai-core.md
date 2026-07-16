backend/
└── ai_core/
    ├── pyproject.toml
    ├── README.md
    ├── LICENSE
    ├── .env.example
    ├── .gitignore
    ├── ruff.toml
    ├── mypy.ini
    ├── pytest.ini
    ├── alembic.ini
    ├── Dockerfile
    ├── docker-compose.yml
    ├── Makefile
    ├── scripts/
    │   ├── dev.sh
    │   ├── dev.ps1
    │   ├── test.sh
    │   ├── test.ps1
    │   ├── lint.sh
    │   ├── lint.ps1
    │   ├── format.sh
    │   ├── format.ps1
    │   ├── migrate.sh
    │   ├── migrate.ps1
    │   ├── seed.sh
    │   └── seed.ps1
    ├── deployments/
    │   ├── k8s/
    │   │   ├── namespace.yaml
    │   │   ├── configmap.yaml
    │   │   ├── secret.yaml
    │   │   ├── deployment.yaml
    │   │   ├── service.yaml
    │   │   ├── hpa.yaml
    │   │   └── ingress.yaml
    │   └── helm/
    │       ├── Chart.yaml
    │       ├── values.yaml
    │       └── templates/
    │           ├── deployment.yaml
    │           ├── service.yaml
    │           ├── configmap.yaml
    │           ├── secret.yaml
    │           ├── hpa.yaml
    │           └── ingress.yaml
    ├── migrations/
    │   ├── env.py
    │   ├── script.py.mako
    │   └── versions/
    ├── ai_core/
    │   ├── __init__.py
    │   ├── app.py
    │   ├── main.py
    │   ├── version.py
    │   ├── settings.py
    │   ├── wiring.py
    │   ├── exceptions.py
    │   ├── constants.py
    │   ├── bootstrap/
    │   │   ├── __init__.py
    │   │   ├── container.py
    │   │   ├── lifecycle.py
    │   │   └── health.py
    │   ├── api/
    │   │   ├── __init__.py
    │   │   ├── deps.py
    │   │   ├── middleware/
    │   │   │   ├── __init__.py
    │   │   │   ├── request_id.py
    │   │   │   ├── auth_context.py
    │   │   │   ├── rate_limit.py
    │   │   │   ├── audit_log.py
    │   │   │   └── error_handler.py
    │   │   ├── routers/
    │   │   │   ├── __init__.py
    │   │   │   ├── health.py
    │   │   │   ├── metrics.py
    │   │   │   ├── chat.py
    │   │   │   ├── agents.py
    │   │   │   ├── tools.py
    │   │   │   ├── memory.py
    │   │   │   ├── rag.py
    │   │   │   ├── workflows.py
    │   │   │   ├── admin.py
    │   │   │   ├── csmarket_pricing.py
    │   │   │   ├── csmarket_listings.py
    │   │   │   ├── csmarket_trades.py
    │   │   │   ├── csmarket_risk.py
    │   │   │   └── csmarket_payments.py
    │   │   └── schemas/
    │   │       ├── __init__.py
    │   │       ├── common.py
    │   │       ├── chat.py
    │   │       ├── agents.py
    │   │       ├── tools.py
    │   │       ├── memory.py
    │   │       ├── rag.py
    │   │       ├── workflows.py
    │   │       ├── csmarket_pricing.py
    │   │       ├── csmarket_listings.py
    │   │       ├── csmarket_trades.py
    │   │       ├── csmarket_risk.py
    │   │       └── csmarket_payments.py
    │   ├── domain/
    │   │   ├── __init__.py
    │   │   ├── models/
    │   │   │   ├── __init__.py
    │   │   │   ├── chat.py
    │   │   │   ├── message.py
    │   │   │   ├── agent.py
    │   │   │   ├── tool.py
    │   │   │   ├── document.py
    │   │   │   ├── embedding.py
    │   │   │   ├── memory_item.py
    │   │   │   ├── workflow.py
    │   │   │   ├── audit_event.py
    │   │   │   ├── csmarket_listing.py
    │   │   │   ├── csmarket_trade.py
    │   │   │   ├── csmarket_fee.py
    │   │   │   ├── csmarket_payment.py
    │   │   │   ├── csmarket_risk_event.py
    │   │   │   └── csmarket_price_snapshot.py
    │   │   ├── events/
    │   │   │   ├── __init__.py
    │   │   │   ├── bus.py
    │   │   │   ├── event_types.py
    │   │   │   └── handlers/
    │   │   │       ├── __init__.py
    │   │   │       ├── audit.py
    │   │   │       ├── memory_sync.py
    │   │   │       ├── metrics.py
    │   │   │       ├── csmarket_pricing_events.py
    │   │   │       ├── csmarket_trade_events.py
    │   │   │       └── csmarket_risk_events.py
    │   │   ├── policies/
    │   │   │   ├── __init__.py
    │   │   │   ├── safety.py
    │   │   │   ├── pii.py
    │   │   │   ├── prompt_injection.py
    │   │   │   ├── tool_guardrails.py
    │   │   │   ├── rbac.py
    │   │   │   ├── anti_fraud.py
    │   │   │   ├── fees.py
    │   │   │   └── pricing_integrity.py
    │   │   └── services/
    │   │       ├── __init__.py
    │   │       ├── chat_service.py
    │   │       ├── agent_service.py
    │   │       ├── tool_service.py
    │   │       ├── memory_service.py
    │   │       ├── rag_service.py
    │   │       ├── workflow_service.py
    │   │       ├── csmarket_pricing_service.py
    │   │       ├── csmarket_listing_service.py
    │   │       ├── csmarket_trade_service.py
    │   │       ├── csmarket_risk_service.py
    │   │       └── csmarket_payment_service.py
    │   ├── orchestration/
    │   │   ├── __init__.py
    │   │   ├── runtime.py
    │   │   ├── planner.py
    │   │   ├── executor.py
    │   │   ├── evaluator.py
    │   │   ├── router.py
    │   │   ├── context_builder.py
    │   │   ├── retries.py
    │   │   └── tracing.py
    │   ├── agents/
    │   │   ├── __init__.py
    │   │   ├── registry.py
    │   │   ├── base.py
    │   │   ├── types.py
    │   │   ├── governance/
    │   │   │   ├── __init__.py
    │   │   │   ├── intent_resolver.py
    │   │   │   ├── agent_governor.py
    │   │   │   └── contradiction_checker.py
    │   │   ├── implementations/
    │   │   │   ├── __init__.py
    │   │   │   ├── analyst.py
    │   │   │   ├── coder.py
    │   │   │   ├── reviewer.py
    │   │   │   ├── ops.py
    │   │   │   └── moderator.py
    │   │   └── prompts/
    │   │       ├── __init__.py
    │   │       ├── system.md
    │   │       ├── analyst.md
    │   │       ├── coder.md
    │   │       ├── reviewer.md
    │   │       └── moderator.md
    │   ├── llm/
    │   │   ├── __init__.py
    │   │   ├── client.py
    │   │   ├── models.py
    │   │   ├── provider_registry.py
    │   │   ├── adapters/
    │   │   │   ├── __init__.py
    │   │   │   ├── openai.py
    │   │   │   ├── ollama.py
    │   │   │   └── local.py
    │   │   ├── prompt/
    │   │   │   ├── __init__.py
    │   │   │   ├── templates.py
    │   │   │   ├── formatter.py
    │   │   │   └── sanitizer.py
    │   │   └── caching/
    │   │       ├── __init__.py
    │   │       ├── key.py
    │   │       ├── store.py
    │   │       └── policy.py
    │   ├── tools/
    │   │   ├── __init__.py
    │   │   ├── registry.py
    │   │   ├── base.py
    │   │   ├── types.py
    │   │   ├── sandbox/
    │   │   │   ├── __init__.py
    │   │   │   ├── runner.py
    │   │   │   ├── filesystem.py
    │   │   │   ├── network.py
    │   │   │   └── policy.py
    │   │   ├── builtin/
    │   │   │   ├── __init__.py
    │   │   │   ├── http.py
    │   │   │   ├── database.py
    │   │   │   ├── vector_search.py
    │   │   │   ├── code_search.py
    │   │   │   ├── math.py
    │   │   │   └── file_store.py
    │   │   └── validators/
    │   │       ├── __init__.py
    │   │       ├── schema_validation.py
    │   │       ├── allowlist.py
    │   │       └── risk_scoring.py
    │   ├── memory/
    │   │   ├── __init__.py
    │   │   ├── interfaces.py
    │   │   ├── short_term.py
    │   │   ├── long_term.py
    │   │   ├── episodic.py
    │   │   ├── semantic.py
    │   │   ├── summarizer.py
    │   │   ├── retention.py
    │   │   ├── privacy.py
    │   │   └── stores/
    │   │       ├── __init__.py
    │   │       ├── postgres.py
    │   │       ├── redis.py
    │   │       └── s3.py
    │   ├── rag/
    │   │   ├── __init__.py
    │   │   ├── pipeline.py
    │   │   ├── ingestion/
    │   │   │   ├── __init__.py
    │   │   │   ├── loaders.py
    │   │   │   ├── chunking.py
    │   │   │   ├── cleaners.py
    │   │   │   └── dedup.py
    │   │   ├── embeddings/
    │   │   │   ├── __init__.py
    │   │   │   ├── encoder.py
    │   │   │   └── batching.py
    │   │   ├── retrieval/
    │   │   │   ├── __init__.py
    │   │   │   ├── vector.py
    │   │   │   ├── hybrid.py
    │   │   │   ├── rerank.py
    │   │   │   └── filters.py
    │   │   ├── index/
    │   │   │   ├── __init__.py
    │   │   │   ├── vector_store.py
    │   │   │   ├── schemas.py
    │   │   │   └── migrations.py
    │   │   └── sources/
    │   │       ├── __init__.py
    │   │       ├── local_files.py
    │   │       ├── git_repo.py
    │   │       └── web_docs.py
    │   ├── workflows/
    │   │   ├── __init__.py
    │   │   ├── registry.py
    │   │   ├── dag.py
    │   │   ├── state.py
    │   │   ├── execution.py
    │   │   └── builtins/
    │   │       ├── __init__.py
    │   │       ├── chat_completion.py
    │   │       ├── rag_answer.py
    │   │       ├── agentic_review.py
    │   │       ├── incident_triage.py
    │   │       ├── csmarket_price_sync.py
    │   │       ├── csmarket_listing_enrichment.py
    │   │       ├── csmarket_trade_execute.py
    │   │       └── csmarket_risk_review.py
    │   ├── security/
    │   │   ├── __init__.py
    │   │   ├── auth/
    │   │   │   ├── __init__.py
    │   │   │   ├── jwt.py
    │   │   │   ├── api_keys.py
    │   │   │   └── rbac.py
    │   │   ├── secrets/
    │   │   │   ├── __init__.py
    │   │   │   ├── keyring.py
    │   │   │   ├── kms.py
    │   │   │   └── rotation.py
    │   │   ├── guardrails/
    │   │   │   ├── __init__.py
    │   │   │   ├── prompt_firewall.py
    │   │   │   ├── output_filter.py
    │   │   │   ├── tool_firewall.py
    │   │   │   └── jailbreak_detection.py
    │   │   └── audit/
    │   │       ├── __init__.py
    │   │       ├── logger.py
    │   │       ├── models.py
    │   │       └── sinks.py
    │   ├── observability/
    │   │   ├── __init__.py
    │   │   ├── logging.py
    │   │   ├── metrics.py
    │   │   ├── tracing.py
    │   │   ├── otel.py
    │   │   ├── prompts/
    │   │   │   ├── __init__.py
    │   │   │   └── redaction.py
    │   │   └── dashboards/
    │   │       ├── grafana/
    │   │       └── loki/
    │   ├── db/
    │   │   ├── __init__.py
    │   │   ├── base.py
    │   │   ├── session.py
    │   │   ├── models.py
    │   │   ├── repositories/
    │   │   │   ├── __init__.py
    │   │   │   ├── chat_repo.py
    │   │   │   ├── agent_repo.py
    │   │   │   ├── memory_repo.py
    │   │   │   ├── rag_repo.py
    │   │   │   ├── audit_repo.py
    │   │   │   ├── csmarket_listing_repo.py
    │   │   │   ├── csmarket_trade_repo.py
    │   │   │   ├── csmarket_price_repo.py
    │   │   │   ├── csmarket_payment_repo.py
    │   │   │   └── csmarket_risk_repo.py
    │   │   └── health.py
    │   ├── integrations/
    │   │   ├── __init__.py
    │   │   ├── redis/
    │   │   │   ├── __init__.py
    │   │   │   └── client.py
    │   │   ├── queue/
    │   │   │   ├── __init__.py
    │   │   │   ├── broker.py
    │   │   │   ├── tasks.py
    │   │   │   └── csmarket_jobs.py
    │   │   ├── storage/
    │   │   │   ├── __init__.py
    │   │   │   ├── s3.py
    │   │   │   └── local.py
    │   │   ├── http/
    │   │   │   ├── __init__.py
    │   │   │   ├── client.py
    │   │   │   └── retry.py
    │   │   ├── steam/
    │   │   │   ├── __init__.py
    │   │   │   ├── client.py
    │   │   │   ├── market_prices.py
    │   │   │   ├── inventory.py
    │   │   │   ├── rate_limits.py
    │   │   │   └── cache_keys.py
    │   │   └── payments/
    │   │       ├── __init__.py
    │   │       ├── interfaces.py
    │   │       ├── btc.py
    │   │       ├── eth.py
    │   │       └── ton.py
    │   ├── utils/
    │   │   ├── __init__.py
    │   │   ├── ids.py
    │   │   ├── time.py
    │   │   ├── hashing.py
    │   │   ├── crypto.py
    │   │   ├── json.py
    │   │   ├── concurrency.py
    │   │   └── validation.py
    │   ├── cli/
    │   │   ├── __init__.py
    │   │   ├── main.py
    │   │   ├── commands/
    │   │   │   ├── __init__.py
    │   │   │   ├── migrate.py
    │   │   │   ├── seed.py
    │   │   │   ├── reindex.py
    │   │   │   ├── doctor.py
    │   │   │   ├── csmarket_price_sync.py
    │   │   │   └── csmarket_reconcile.py
    │   │   └── printers.py
    │   └── csmarket/
    │       ├── __init__.py
    │       ├── contracts/
    │       │   ├── __init__.py
    │       │   ├── pricing.py
    │       │   ├── listings.py
    │       │   ├── trades.py
    │       │   ├── payments.py
    │       │   └── risk.py
    │       ├── pricing/
    │       │   ├── __init__.py
    │       │   ├── steam_price_feed.py
    │       │   ├── normalizer.py
    │       │   ├── cache.py
    │       │   └── anomalies.py
    │       ├── trades/
    │       │   ├── __init__.py
    │       │   ├── orchestrator.py
    │       │   ├── state_machine.py
    │       │   ├── escrow.py
    │       │   ├── settlement.py
    │       │   └── reconciliation.py
    │       ├── fees/
    │       │   ├── __init__.py
    │       │   ├── calculator.py
    │       │   ├── policy.py
    │       │   └── ledger.py
    │       └── risk/
    │           ├── __init__.py
    │           ├── scoring.py
    │           ├── rules.py
    │           ├── velocity_limits.py
    │           └── signals.py
    └── tests/
        ├── __init__.py
        ├── conftest.py
        ├── unit/
        │   ├── __init__.py
        │   ├── test_orchestration.py
        │   ├── test_agents.py
        │   ├── test_tools.py
        │   ├── test_memory.py
        │   ├── test_rag.py
        │   ├── test_csmarket_fees.py
        │   └── test_csmarket_pricing.py
        ├── integration/
        │   ├── __init__.py
        │   ├── test_api_chat.py
        │   ├── test_api_agents.py
        │   ├── test_api_rag.py
        │   ├── test_security_guardrails.py
        │   ├── test_api_csmarket_trades.py
        │   └── test_api_csmarket_pricing.py
        └── e2e/
            ├── __init__.py
            ├── test_workflows.py
            ├── test_observability.py
            └── test_csmarket_trade_flow.py
