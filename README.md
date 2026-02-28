<div align="center">
  <img src="./CodeMantle.png" alt="CodeMantle Logo" width="200" height="200">
  <h1>CodeMantle</h1>
  <p><strong>Open-source remote orchestration platform for OpenCode runtimes</strong></p>
  <p>Secure reverse tunnel model · Compact protocol contracts · Policy-aware session control</p>
</div>

---

CodeMantle is an open-source remote orchestration platform for OpenCode runtimes with a secure reverse tunnel model, compact protocol contracts, and policy-aware session control.

## Monorepo layout

- `apps/control-plane`: WebSocket + HTTP control plane, session orchestration, config registry/compiler, policy enforcement gates.
- `apps/desktop-app`: Tauri desktop setup app and sidecar launcher for the agent daemon.
- `packages/agent-daemon`: Host daemon that connects outbound to the control plane and enforces local security boundaries.
- `packages/codemantle`: Unified orchestrator CLI that routes to panel and agent flows.
- `docs/`: Architecture, protocol pointers, deployment and security references.
- `.github/workflows/`: CI and release workflows for each releasable app/package.

## Installation

Install packages via npm:

```bash
# Control plane (panel)
npm install -g @codemantle/panel

# Agent daemon
npm install -g @codemantle/agent-daemon

# Unified orchestrator CLI (includes both panel and agent)
npm install -g codemantle
```

Or install locally in your project:

```bash
npm install @codemantle/panel
npm install @codemantle/agent-daemon
npm install codemantle
```

## Package Overview

| Package | Purpose | Install Command | Quick Start |
|---------|---------|-----------------|-------------|
| `@codemantle/panel` | WebSocket control plane, HTTP API, UI | `npm install -g @codemantle/panel` | `npx @codemantle/panel start` |
| `@codemantle/agent-daemon` | Host daemon with reverse tunnel | `npm install -g @codemantle/agent-daemon` | `npx @codemantle/agent-daemon --setup` |
| `codemantle` | Unified orchestrator CLI | `npm install -g codemantle` | `npx codemantle --panel` / `npx codemantle --agent` |

## Quickstart

Requirements:

- Node.js 20+
- npm 10+
- (Desktop release) Rust toolchain + Tauri prerequisites

Install and build per component:

```bash
npm ci --prefix apps/control-plane
npm run build --prefix apps/control-plane

npm ci --prefix packages/agent-daemon
npm run build --prefix packages/agent-daemon

npm ci --prefix apps/desktop-app
npm run build --prefix apps/desktop-app
```

Optional workspace scripts:

```bash
npm run build
npm run test
```

Panel package quickstart:

```bash
npx @codemantle/panel start
```

If no `.env` exists, the panel CLI prompts for setup values and writes one for future runs.

Unified orchestrator quickstart:

```bash
npm install codemantle
npx codemantle --panel
npx codemantle --agent
```

## Architecture and contracts

- Wire protocol (`v=1`) is backwards compatible and additive-first.
- Control-plane to daemon contract remains compact JSON envelopes over WebSocket.
- Session lifecycle, snapshot continuity, centralized config push, and JIT kill-switch are preserved.
- Path and process boundaries remain daemon-enforced and zero-trust by default.

See:

- `docs/architecture.md`
- `docs/protocol.md`
- `docs/security-model.md`
- `docs/deployment.md`

## Component release matrix

- `apps/control-plane`: deployable runtime artifact and npm package (`@codemantle/panel`).
- `apps/desktop-app`: first-class desktop release artifact (Tauri Windows `.exe` and macOS `.dmg`).
- `packages/agent-daemon`: releasable daemon binaries plus npm launcher wrapper for binary distribution.
- `packages/codemantle`: releasable orchestrator CLI package (`codemantle`) with `codemantle` command.

## Release/tag strategy

- Unified semantic tag trigger: `vX.Y.Z` starts all release workflows.
- Manual dispatch remains available for all release workflows.
- Optional signing hooks are wired via GitHub Actions secrets and are skipped safely when unset.

## Security model highlights

- Daemon authenticates to control plane with nonce + HMAC handshake.
- Human access to control-plane UI/API is protected by configurable auth (`AUTH_MODE`), local email/password login, and configurable Authy-compatible RFC6238 MFA (`AUTH_MFA_ENABLED`, `AUTH_OWNER_2FA_PASSKEY`).
- Session cookies are HttpOnly with CSRF tokens for mutating API routes and role-based route authorization (`owner/admin/operator/viewer`).
- JIT session credentials are scoped, short lived, and revocable (`jk`/`jv`).
- Config push uses deterministic digest and policy-mode aware validation.
- Directory operations enforce strict root/path/symlink boundaries.

## Contributing

Please read:

- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SECURITY.md`

## License

Apache-2.0 (`LICENSE`).
