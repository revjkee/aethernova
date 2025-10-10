# Changelog
All notable changes to this project will be documented in this file.

The format is based on:
- Keep a Changelog (https://keepachangelog.com/en/1.1.0/)
- Semantic Versioning 2.0.0 (https://semver.org/spec/v2.0.0.html)

## [Unreleased]
### Added
- Finality Gadget (epochs + checkpoints) with light-client proofs.
- Fee Market (priority policy + estimator) and parallel optimistic executor.
- ZK privacy (transparent/shielded modes, commitments/nullifiers).
- UTXO subsystem (optional) alongside account-based state.
- Helm chart values for `btc2_finality`, `parallel_exec`, `zk_priv_tx`.
- OpenTelemetry dashboards and Prometheus rules for consensus/txpool/zk.
- SLSA provenance workflow and hardened CI security gates.
- Key management ADR: seed / threshold / HSM / social recovery.

### Changed
- Unified gas model (CPU/IO/Storage) with deterministic limits for WASM/EVM.
- Consolidated RPC batching and fee estimation endpoints.
- Hardened K8s NetworkPolicy and PodDisruptionBudget defaults.

### Fixed
- Snapshot state hashing stability across platforms (endianness-safe).
- Deterministic serialization for block/tx formats.

### Security
- Zero-Trust supply-chain policy, mandatory attestation on release artifacts.
- Wallet keystore: threshold signatures support and HSM integration.

## [0.1.0] - 2025-09-08
### Added
- Initial public workspace layout with node/vm/zk/bridge/governance/sdk.
- Devnet scripts (`devnet_up.sh`, `devnet_down.sh`, `start_node.sh`).
- Observability baseline (OTEL collector, dashboards, ServiceMonitor).
- E2E smoke tests and fuzz target for tx codec.
