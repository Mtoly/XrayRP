# XrayRP architecture map

XrayRP runs panel-managed proxy nodes on top of Xray. It translates normalized panel snapshots into local Node runtime state and reports runtime observations back to the panel.

## Entry points

- `cmd/`: CLI entry points, configuration loading, and hot reload.
- `panel/`: runtime configuration planning, static-node mode, machine mode, and top-level lifecycle ownership.

## Runtime boundaries

- `api/`: panel adapters and normalized panel-facing data contracts.
- `api/internal/panelhttp/`: Panel transport mechanics, including response limits, retries, timeouts, and credential redaction.
- `service/controller/`: Node runtime state, sync action submission, Authoritative snapshot synchronization, apply, reporting, and runtime updates.
- `service/machine/`: machine-mode discovery, reconciliation, per-node lifecycle, shared WebSocket ownership, and reporting.
- `service/anytls/`, `service/tuic/`, `service/hysteria2/`: Specialized runtime lifecycle and protocol-specific configuration.
- `service/internal/`: shared lifecycle and WebSocket helpers.

## Cross-cutting state

- `common/limiter/`: admission, device, traffic, and speed-limit state.
- `common/rule/`: audit rule ownership and result draining.
- `common/mylego/`: certificate acquisition, storage, renewal, and filesystem transactions.
- `app/`: Xray-core integration and local dispatcher behavior.

## Core invariants

- A fetched candidate becomes an Applied node value only after runtime apply succeeds.
- Readers observe either the previous valid generation or the complete next generation.
- Static `Nodes` mode and enabled `MachineConfig` mode are mutually exclusive.
- Polling, WebSocket, reconnect, and manual triggers converge through the same Sync action submission and apply path.
- Runtime replacement prepares and validates a candidate before publication, then retires the previous runtime.
