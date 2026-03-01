# @codemantle/agent-daemon

[![npm version](https://img.shields.io/npm/v/@codemantle/agent-daemon?color=cb3837&logo=npm)](https://www.npmjs.com/package/@codemantle/agent-daemon)
[![npm downloads](https://img.shields.io/npm/dm/@codemantle/agent-daemon?color=blue)](https://www.npmjs.com/package/@codemantle/agent-daemon)
[![License](https://img.shields.io/github/license/XQuestCode/CodeMantle)](../../LICENSE)

CodeMantle host daemon package.

This daemon connects outbound to the control plane, executes session operations locally, and enforces filesystem/process safety boundaries on the host.

## What this package includes

- Reverse WebSocket client for control-plane connectivity.
- OpenCode runtime lifecycle and session orchestration.
- Local path/root/symlink boundary enforcement.
- JIT credential handling and revocation support.
- npm launcher that resolves and runs platform binaries.

## Install and run

Run directly:

```bash
npx @codemantle/agent-daemon
```

Or install globally:

```bash
npm install -g @codemantle/agent-daemon
codemantle-agent
```

## Initial setup

Run interactive setup:

```bash
codemantle-agent --setup
```

This setup flow probes local dependencies, prompts for required values, and writes `.env` into your workspace.

## Required environment variables

- `CONTROL_PLANE_URL` (`ws://` or `wss://` endpoint)
- `AGENT_AUTH_TOKEN` (must match a token in panel `VALID_TOKENS`)

Common runtime variables:

- `AGENT_PROJECT_ROOT` (root boundary for filesystem operations)
- `DEVICE_ID` (stable host identity; auto-generated if absent)
- `OPENCODE_COMMAND` (default `opencode`)
- `OPENCODE_HOST` (default `127.0.0.1`)
- `OPENCODE_START_PORT` (default `4096`)
- `REQUEST_TIMEOUT_MS`
- `RECONNECT_BASE_MS`
- `RECONNECT_MAX_MS`

## npm wrapper and binary distribution

The npm package launches a platform-specific binary and verifies downloaded artifacts with SHA-256 checksums from release `checksums.txt`.

Distribution controls:

- `CODEMANTLE_AGENT_BINARY_BASE_URL` to use a private mirror.
- `CODEMANTLE_AGENT_INSTALL_DIR` to change binary cache location.
- `CODEMANTLE_AGENT_BINARY_PATH` to run an explicit local binary.
- `CODEMANTLE_AGENT_SKIP_DOWNLOAD=1` to skip postinstall fetch.

Supported binary targets:

- Windows x64
- macOS x64
- macOS arm64
- Linux x64
- Linux arm64

## Keep it running

PM2 example:

```bash
pm2 start "codemantle-agent" --name codemantle-agent
pm2 save
pm2 startup
```

systemd example:

```ini
[Unit]
Description=CodeMantle Agent Daemon
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/codemantle-agent
EnvironmentFile=/opt/codemantle-agent/.env
ExecStart=/usr/bin/env codemantle-agent
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Development

```bash
npm ci
npm run dev
```

Build TypeScript and launcher bundle:

```bash
npm run build
```

Build standalone binaries with `pkg`:

```bash
npm run pkg
```

## Troubleshooting

- `AUTH` or handshake failures: verify `AGENT_AUTH_TOKEN` matches panel `VALID_TOKENS`.
- connection retries: verify `CONTROL_PLANE_URL` and network egress.
- missing binary / checksum mismatch: verify release availability or set `CODEMANTLE_AGENT_BINARY_BASE_URL`.
- unsupported platform error: use a supported OS/arch combo listed above.

For protocol and security details, see:

- https://github.com/XQuestCode/codemantle/blob/main/PROTOCOL.md
- https://github.com/XQuestCode/codemantle/blob/main/docs/architecture.md
- https://github.com/XQuestCode/codemantle/blob/main/docs/security-model.md
