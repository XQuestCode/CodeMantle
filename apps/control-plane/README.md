# @codemantle/panel

[![npm version](https://img.shields.io/npm/v/@codemantle/panel?color=cb3837&logo=npm)](https://www.npmjs.com/package/@codemantle/panel)
[![npm downloads](https://img.shields.io/npm/dm/@codemantle/panel?color=blue)](https://www.npmjs.com/package/@codemantle/panel)
[![License](https://img.shields.io/github/license/XQuestCode/CodeMantle)](../../LICENSE)

CodeMantle control-plane service as an npm package.

It runs the WebSocket control channel, HTTP API, and UI used to orchestrate connected `@codemantle/agent-daemon` instances.

## What this package includes

- Reverse WebSocket server for daemon tunnels.
- HTTP API for orchestration and policy-aware actions.
- Static web UI for device/session operations.
- First-run env bootstrap (`.env` init) and env diagnostics commands.

## Install

Run directly with `npx` (recommended):

```bash
npx @codemantle/panel start
```

Or install globally:

```bash
npm install -g @codemantle/panel
codemantle-panel start
```

## First run and env bootstrap

If no `.env` exists, `codemantle-panel start` launches an interactive setup in TTY mode and writes `.env` for future runs.

Explicit init:

```bash
codemantle-panel init --env-file /opt/codemantle/.env
```

Headless init:

```bash
codemantle-panel init --non-interactive --env-file /opt/codemantle/.env \
  --set AUTH_OWNER_EMAIL=owner@example.com \
  --set AUTH_OWNER_PASSWORD="replace-me" \
  --set VALID_TOKENS="replace-with-secure-token"
```

Notes:

- `AUTH_OWNER_PASSWORD` is converted to `AUTH_OWNER_PASSWORD_HASH` on generation.
- Generated files are written with restrictive permissions where supported.
- `.env` is appended to local `.gitignore` when missing.

## CLI reference

```bash
codemantle-panel [start] [--env-file <path>] [--config-dir <dir>] [--non-interactive]
codemantle-panel init [--env-file <path>] [--config-dir <dir>] [--set KEY=VALUE] [--yes] [--force]
codemantle-panel migrate-env [--env-file <path>] [--write]
codemantle-panel doctor [--env-file <path>]
```

## Required and recommended environment variables

Required:

- `VALID_TOKENS` (comma-separated daemon auth tokens)
- `JIT_CREDENTIAL_SIGNING_KEY`
- `AUTH_OWNER_EMAIL`
- `AUTH_OWNER_PASSWORD_HASH` (or `AUTH_OWNER_PASSWORD`)

Core runtime:

- `CONTROL_PLANE_PORT` (default `8787`)
- `CONTROL_PLANE_API_PORT` (default `8788`)
- `HEARTBEAT_SECONDS`
- `REQUEST_TIMEOUT_MS`
- `MAX_API_BODY_BYTES`
- `MAX_PROMPT_CHARS`

Auth and session security:

- `AUTH_MODE` (`local`, `disabled`, `oidc` stub)
- `AUTH_MFA_ENABLED`
- `AUTH_MFA_PROVIDER` (`authy` or `totp`, RFC6238)
- `AUTH_MFA_REQUIRE_FOR_ALL_USERS`
- `AUTH_OWNER_2FA_PASSKEY` (recommended)
- `AUTH_OWNER_TOTP_SECRET` (legacy alias)
- `AUTH_COOKIE_SECURE` (set `true` for TLS/internet deployments)
- `AUTH_SESSION_COOKIE_NAME`
- `AUTH_CSRF_COOKIE_NAME`

Schema/versioning:

- `PANEL_ENV_SCHEMA_VERSION` (managed by init/migrate tooling)

See `.env.example` for defaults and formatting.

## 24/7 operation

PM2 baseline:

```bash
pm2 start "npx @codemantle/panel start --env-file /opt/codemantle/.env --non-interactive" --name codemantle-panel
pm2 save
pm2 startup
```

systemd baseline:

```ini
[Unit]
Description=CodeMantle Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/codemantle
EnvironmentFile=/opt/codemantle/.env
ExecStart=/usr/bin/env npx @codemantle/panel start --env-file /opt/codemantle/.env --non-interactive
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Validation and upgrades

Check env health:

```bash
codemantle-panel doctor --env-file /opt/codemantle/.env
```

Preview env migration output:

```bash
codemantle-panel migrate-env --env-file /opt/codemantle/.env
```

Apply migration in place:

```bash
codemantle-panel migrate-env --env-file /opt/codemantle/.env --write
```

## Development

```bash
npm ci
npm run dev
```

Build and run built output:

```bash
npm run build
npm run start
```

## Security and compatibility

- Protocol contract remains additive-first (`v=1`).
- Daemon trust boundaries (path/process guardrails) remain daemon-enforced.
- For production, run behind TLS/reverse proxy and keep `AUTH_COOKIE_SECURE=true`.

For full architecture and security details, see:

- https://github.com/XQuestCode/codemantle/blob/main/docs/architecture.md
- https://github.com/XQuestCode/codemantle/blob/main/docs/protocol.md
- https://github.com/XQuestCode/codemantle/blob/main/docs/security-model.md
