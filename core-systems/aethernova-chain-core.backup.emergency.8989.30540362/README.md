/aethernova-chain-core/README.md

# Aethernova Chain Core (BTC 2.0 Profile)

Путь: `/aethernova-chain-core/README.md`

## Кратко
Aethernova Chain Core — модульное L1-ядро с профилем **BTC 2.0**: финализация за секунды (finality gadget + checkpoints), низкие комиссии (fee-market), параллельное исполнение, опциональные zk-переводы, строгая токеномика с hard cap **22 000 000 AEV** и Zero-Trust DevSecOps.

## Ключевые возможности
- Консенсус: Tendermint-like/HotStuff c **finality gadget** и чекпойнтами.
- P2P: Kademlia DHT, gossip, защитные сетевые политики.
- Исполнение: WASM runtime + EVM-адаптер, **параллельный executor** (read/write-set).
- Приватность: **опциональные** zk-транзакции (commitments/nullifiers), режимы transparent/shielded.
- Токеномика: hard cap `22,000,000 AEV`, halving по блокам.
- Мост: релейер с верификацией заголовков (merkle/light-client).
- Наблюдаемость: OpenTelemetry, Prometheus, дашборды.
- Supply chain security: SLSA provenance, воспроизводимые сборки.
- SDK: Rust/Python/TypeScript клиенты.
- Тестирование: unit/integration/fuzz/e2e, smoke-тест devnet.

## Архитектура (папки)
- `/node/` — узел: `consensus/`, `p2p/`, `txpool/`, `rpc/`, `storage/`, `state/`, `crypto/`, `telemetry/`.
- `/vm/` — `src/{executor.rs, gas.rs}`, `wasm/`, `evm/`.
- `/contracts/` — Solidity контракты: токен, governance, privacy-верификатор.
- `/bridge/` — релейер и L1-контракты моста.
- `/governance/` — предложения, голосование, казначейство, параметры.
- `/sdk/` — `rust/`, `python/`, `typescript/`.
- `/zk/` — `circuits/`, `prover/`, `verifier/`.
- `/ops/` — Docker, K8s, Helm chart, Terraform, OTEL.
- `/configs/` — `chain.toml`, `node.toml`, `p2p.toml`, `rpc.toml`, `telemetry.yaml`, `env/`.
- `/tests/` — unit, integration, fuzz, e2e.
- `/docs/` — ADR, протокол, runbooks, security, scaling.

## Требования
- Rust `stable` (см. `/aethernova-chain-core/rust-toolchain.toml`).
- Cargo, Make, Docker, optional: Kubernetes/Helm/Terraform.
- Node.js (для `/contracts/scripts`, `/sdk/typescript`), Python 3.10+ (для `/sdk/python`).

## Сборка
```bash
cd /aethernova-chain-core
make build          # эквивалент cargo build --release для воркспейса
cargo build --release

Локальный Devnet
# поднять devnet с профилями BTC 2.0:
bash /aethernova-chain-core/scripts/devnet_up.sh \
  --finality-gadget \
  --parallel-exec \
  --zk-priv-tx

# остановить
bash /aethernova-chain-core/scripts/devnet_down.sh

Запуск узла
bash /aethernova-chain-core/scripts/start_node.sh \
  --config /aethernova-chain-core/configs/node.toml \
  --chain  /aethernova-chain-core/genesis.json \
  --finality-gadget --parallel-exec --zk-priv-tx

Конфигурация

/configs/chain.toml — эпохи, финальность, halving (prod: read-only).

/configs/node.toml — профили узла: btc2_finality, parallel_exec, zk_priv_tx.

/configs/p2p.toml — лимиты, bootstrap, bans.

/configs/rpc.toml — JSON-RPC/gRPC, батч-лимиты, CORS.

/configs/telemetry.yaml — OTEL/Prometheus.

/configs/env/{dev,staging,prod}.toml — окружения.

Токеномика (сводно)

Hard cap: 22,000,000 AEV.

Block time: 2 s.

Halving: каждые 63,072,000 блоков (~4 года).

Начальная субсидия блока: 0.17430000 AEV (геометрическое убывание).

Политика комиссий: burn/treasury/split (по умолчанию split 50/50 — настраивается governance).
Детали: /aethernova-chain-core/docs/ADR/0006-tokenomics-halving.md, /tokenomics/models/emission.md.

Приватность

Режимы: transparent и shielded.

ZK-компоненты: /zk/circuits/{halo2,plonk}, /zk/prover/src/prove.rs, /zk/verifier/src/verify.rs.

Хост-функции: /vm/wasm/host_fns.rs.

Контракты проверки: /contracts/solidity/privacy/ShieldedTransferVerifier.sol.
Формат транзакций: /docs/protocol/tx_format.md.

Управление ключами

Базовый уровень: seed (совместимость HD-кошельков).

Продвинутый: threshold/multisig, HSM/TEE, social recovery.

Реализация: /wallet/src/keystore.rs, ADR: /docs/ADR/0009-key-management.md.

Мост

Релейер: /bridge/relayer/src/{main.rs, adapters/, proofs/}.

Контракты: /bridge/contracts/solidity/{Bridge.sol, IBridge.sol}.

Лёгкие клиенты: /node/src/consensus/finality/light_client.rs.

Наблюдаемость и безопасность

OTEL collector: /ops/otel/collector-config.yaml.

Дашборды: /ops/otel/dashboards/*.json.

K8s ServiceMonitor/Prometheus rules: /ops/k8s/base/{servicemonitor.yaml,prometheus-rules.yaml}.

SLSA, provenance: /.github/workflows/provenance-slsa.yaml.

Политика безопасности: /docs/SECURITY.md.

Тестирование
cargo test --workspace
cargo test -p node
cargo test -p vm


E2E: /tests/e2e/{devnet_smoke.rs, finality_checkpoint.rs, private_transfer.rs}.

Fuzz: /tests/fuzz/tx_codec.rs.

Сборка контейнера
docker build -f /aethernova-chain-core/ops/docker/Dockerfile -t aethernova/node:latest .
docker-compose -f /aethernova-chain-core/ops/docker/docker-compose.yaml up -d

Деплой в Kubernetes

Helm chart: /ops/helm/aethernova-chain-core.

Базовые манифесты: /ops/k8s/base.

Overlays: /ops/k8s/overlays/{dev,staging,prod}.

Вклады и правила

CONTRIBUTING: /docs/CONTRIBUTING.md.

Код-стайл: mypy/ruff (если применимо), pre-commit.

Лицензия: см. /aethernova-chain-core/LICENSE (Apache-2.0).