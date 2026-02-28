# Security model

## Trust boundaries

- Control plane is authoritative for authentication, authorization, and orchestration policy.
- Agent daemon is authoritative for local host execution boundaries.
- Desktop app is an operator client and never bypasses daemon policy checks.

## Authentication and transport

- Daemon initiates reverse WebSocket connection to control plane.
- Handshake uses nonce + timestamp + HMAC verification (`h1`/`h2`).
- Replay and skew protections are enforced during auth.
- Protocol mismatch guard returns explicit `UPDATE_REQUIRED` and closes safely when daemon version is below required floor.
- Production deployments should use `wss` and strict token rotation.
- Human auth is env-driven (`AUTH_MODE`): local mode supports email/password with scrypt hashing and configurable Authy-compatible RFC6238 2FA (`AUTH_MFA_ENABLED`, `AUTH_MFA_PROVIDER`, `AUTH_OWNER_2FA_PASSKEY`).
- Session cookies are HttpOnly + Secure (when enabled), include TTL + inactivity timeout, and require CSRF token validation on mutating routes.
- Login path includes rate limiting and lockout window to reduce brute-force risk.

## Authorization and tenancy

- Tenant checks occur before command dispatch.
- Device routing must remain tenant scoped.
- Route-level RBAC is enforced (`owner/admin/operator/viewer`) before sensitive dispatch (`/devices/*`, `/session/*`, `/config/*`, proxy routes, setup save).
- Preview proxy and session snapshots are bound to authenticated principal ownership and should include tenant/user claims in federated identity environments.

## Daemon local enforcement

- Root alias is constrained to configured project root.
- Absolute path, traversal, and symlink escapes are rejected.
- Config apply path is allowlisted and validated.
- JIT credentials are scoped, TTL-bounded, and revocable via kill switch.

## Data integrity

- Protocol contracts remain additive-first (`v=1`).
- Durable state belongs in Postgres for persistence-backed control planes.
- Event streams remain append-only and are published via outbox for atomicity.
- Command idempotency keys (`deviceId + requestId`) prevent duplicate side effects.

## Distribution integrity

- Agent npm wrapper verifies downloaded binary SHA-256 checksums against release `checksums.txt`.
- Panel npm package (`@codemantle/panel`) is published from the tagged release workflow and should use npm provenance (`--provenance`) when token support is configured.
- Desktop updater payloads are signed using Tauri updater keypair (`TAURI_SIGNING_PRIVATE_KEY` + published updater `pubkey`).
