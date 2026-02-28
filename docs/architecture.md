# CodeMantle architecture

## System context

CodeMantle uses a reverse-connect model where `packages/agent-daemon` opens an outbound WebSocket tunnel to `apps/control-plane`. This keeps inbound firewall requirements low and centers authorization decisions at the control plane.

Primary runtime planes:

- Control plane: contract enforcement, orchestration APIs, template compilation, policy and audit gates.
- Agent daemon: local execution boundary, filesystem/process controls, OpenCode lifecycle and session continuity.
- Desktop app: setup UX, sidecar lifecycle management, and local operator controls.

## Decision boundaries

### API contracts and compatibility

- Wire protocol remains `v=1` and additive-first.
- New behaviors are introduced via optional fields or discriminators (`k`, `ph`, `sc`, `pm`) instead of envelope breaking changes.
- HTTP orchestration endpoints are stable path contracts and can add optional request/response fields without removing existing fields.

### OpenCodeInstance CRD evolution boundary

CodeMantle currently runs a control-plane + daemon topology and does not require Kubernetes as a hard dependency. For Kubernetes-backed deployments, `OpenCodeInstance` should be modeled as an optional projection layer with strict boundaries:

- CRD owns desired state for runtime placement and health intent.
- Control plane owns protocol/session semantics and policy enforcement.
- Daemon owns local zero-trust execution boundaries.

Compatibility rules for future `OpenCodeInstance`:

- Additive schema changes only for minor versions.
- Conversion webhooks required for breaking shape changes.
- Reconciliation must not mutate session protocol payloads or bypass daemon validation gates.

### Data model integrity (Postgres + event stream)

Recommended invariants for persistence-backed deployments:

- Postgres is source of truth for durable entities (devices, templates, template versions, session metadata, policy snapshots).
- Event stream is append-only for timeline/audit replay and read model fanout.
- Idempotency keys for command handling (`deviceId + requestId`) prevent duplicate side effects.
- Outbox pattern should bridge Postgres writes to event stream publication atomically.

### Multi-tenant isolation and authorization

- Tenant boundary is enforced at control-plane API/auth layer before any tunnel command dispatch.
- Device records and active socket routing must be tenant-scoped.
- Config templates, MCP registry entries, and session snapshots are tenant-partitioned.
- Preview proxy and snapshot replay remain owner-scoped and should be extended to tenant + user claims in federated identity environments.

## Component interactions

1. Daemon authenticates with nonce + HMAC handshake.
2. Control plane binds socket to device identity and tracks liveness.
3. API-triggered orchestration dispatches compact protocol commands (`si`, `st`, `cc`, `jk`, etc.).
4. Daemon enforces local policy boundaries and returns compact outcomes.
5. UI and operational APIs consume current state and replay streams.

## Non-goals

- No direct inbound remote shell into host from control plane.
- No bypass around daemon path and process guards.
- No protocol contract breaks without explicit version rollover.
