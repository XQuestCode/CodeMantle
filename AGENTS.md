# Agent Guidelines for CodeMantle

This document provides guidance for AI coding assistants working in the CodeMantle repository.

## Project Overview

CodeMantle enables multi-device OpenCode functionality, allowing developers to work from anywhere by coordinating OpenCode instances across multiple machines. The system consists of:

- **codemantle** (CLI): Orchestrator for launching and managing the agent daemon
- **agent-daemon**: Host daemon that manages OpenCode processes and communicates with the control plane
- **control-plane**: WebSocket server that coordinates agents and handles authentication
- **desktop-app**: Tauri-based desktop application for managing connections

## Build and Test Commands

### Root Level
```bash
npm run build                    # Build all workspaces
npm run dev:control-plane        # Dev mode for control plane
npm run dev:agent-daemon         # Dev mode for agent daemon
npm run dev:desktop-app          # Dev mode for desktop app
```

### Per-Workspace
```bash
npm run build --workspace @codemantle/panel
npm run dev --workspace @codemantle/agent-daemon
```

### Desktop App
```bash
cd apps/desktop-app
npm run tauri:dev                # Dev with hot reload
npm run tauri:build              # Production build
```

### Testing
**No test framework is currently configured.** Do not speculate on future test structure.

### Linting
**No ESLint/Prettier configuration exists.** Follow observed patterns in the codebase (see Code Style below).

## Code Style Guidelines

### Imports
- Use `node:` prefix for Node.js built-ins: `import fs from 'node:fs'`
- Local imports require `.js` extension (ES module requirement): `import { foo } from './utils.js'`
- Group imports: built-ins → external packages → local modules

### TypeScript
- Use `interface` for object shapes, `type` for unions/aliases
- Use `Record<string, unknown>` for arbitrary objects
- Strict mode is enabled (`exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`)
- Prefer explicit return types on exported functions

### Naming Conventions
- Files: kebab-case (`session-manager.ts`)
- Functions/variables: camelCase (`getUserSession`)
- Interfaces/types: PascalCase (`WebSocketMessage`)
- Constants: UPPER_SNAKE_CASE (`WS_PROTOCOL_VERSION`)

### Formatting (Observed Patterns)
- 2-space indentation
- Semicolons required
- Double quotes for strings
- Trailing commas in multi-line objects/arrays

## Error Handling

### Consistent Response Pattern
```typescript
// Success
return { o: 1, result: data };

// Error
return { o: 0, m: 'Error message' };
```

### Try-Catch Patterns
```typescript
try {
  // operation
} catch (error) {
  if (error instanceof Error) {
    return { o: 0, m: error.message };
  }
  return { o: 0, m: 'Unknown error' };
}
```

### Early Returns
Prefer early returns for error conditions to reduce nesting.

## Architecture Patterns

### WebSocket Protocol

**Protocol Version:** `WS_PROTOCOL_VERSION = 1`

**Message Envelope:**
```typescript
{
  v: 1,                    // Protocol version
  t: "messageType",        // Message type (discriminator)
  i?: string,              // Request ID for request/response correlation
  ...fields                // Type-specific fields
}
```

**Control Plane URLs:**
- Production: `wss://codemantle.cloud/ws`
- Development: `ws://127.0.0.1:8787`

**Handshake Flow:**
1. Agent → Control Plane: `h1` message with HMAC signature
2. Control Plane → Agent: `h2` message with authentication result
3. Bidirectional messaging after successful handshake

**Request/Response Correlation:**
Use the `i` field to match responses with requests. Implement timeout mechanisms for pending requests.

### OpenCode Integration

CodeMantle's core purpose is managing OpenCode instances across devices. The agent-daemon handles all OpenCode lifecycle management.

#### Process Management
**Command Execution:**
```typescript
spawn(OPENCODE_COMMAND, [
  "serve",
  "--hostname", host,
  "--port", port,
  "--print-logs"
], {
  cwd: folderPath,
  env: { ...process.env, ...customEnv },
  stdio: ["ignore", "pipe", "pipe"]
})
```

**Port Allocation:**
- Starts from `OPENCODE_START_PORT` (default: 4096)
- Scans 200 ports for availability
- One process per unique folder path

**Health Checks:**
- Exponential backoff: 250ms → 500ms → 1000ms
- 15-second timeout
- HTTP GET to `http://${host}:${port}/health`

**Session URL Extraction:**
Captures from stdout/stderr using regex: `/https?:\/\/(127\.0\.0\.1|localhost):\d+\/[A-Za-z0-9_-]+\/session/`

#### Environment Variables

**Standard Variables:**
- `OPENCODE_COMMAND`: Path to OpenCode executable
- `OPENCODE_HOST`: Server hostname
- `OPENCODE_START_PORT`: Starting port for allocation
- `OPENCODE_PROVIDER_ID`: AI provider identifier
- `OPENCODE_MODEL_ID`: AI model identifier

**JIT (Just-In-Time) Credentials:**
- `OPENCODE_SESSION_TOKEN`: Short-lived authentication token
- `OPENCODE_JIT_TOKEN_EXPIRES_AT`: ISO 8601 expiration timestamp
- `OPENCODE_JIT_SCOPE`: Access scope for the token

**Custom Environment Variables:**
- Maximum 8 custom key-value pairs
- Maximum 2KB per value
- Whitelist-controlled keys

#### Session Lifecycle

1. **Startup:** Port allocation → Process spawn → Server registration → Log capture → Health checks
2. **Running:** Continuous log streaming, health monitoring, registry persistence
3. **Registry:** `.opencode-session-registry.json` enables restart recovery
4. **Termination:** Triggered by explicit request, crash, health failure, or JIT expiry

#### JIT Credential Management

- **TTL:** 15 seconds to 3600 seconds
- **Expiry:** Automatic via `setTimeout`, kills OpenCode process
- **Kill-Switch:** Immediate revocation support
- **Fingerprinting:** SHA-256 for credential tracking
- **Redaction:** All sensitive values logged as `***REDACTED***`

#### Log Storage

**Plain Text Logs:**
- Path: `.opencode-session-log`
- Max size: 1MB
- Auto-trimmed when exceeding limit

**Structured Logs (JSONL):**
- Path: `.opencode-session-snapshot.jsonl`
- Max size: 5MB
- Events: `{ t: string, ts: number, ...data }`

#### HTTP API (Agent Daemon)

The agent-daemon exposes a local HTTP server for control:

- `GET /health` - Health check endpoint
- `POST /opencode/start` - Start OpenCode session
- `POST /opencode/stop` - Stop OpenCode session
- `GET /opencode/logs` - Retrieve session logs
- `GET /opencode/status` - Get session status

## Security Considerations

### CRITICAL Security Items

1. **Authentication Tokens:** Never log, commit, or expose `OPENCODE_SESSION_TOKEN` or WebSocket auth tokens
2. **JIT Credentials:** Automatically expire, but implement kill-switch for immediate revocation
3. **Path Traversal:** Always validate paths with `isPathWithinRoot()` and check symlinks via `realpath()`
4. **OpenCode Isolation:** Each OpenCode process is isolated per folder with separate ports
5. **Privileged Ports:** Never allow port allocation below 1024
6. **Environment Variables:** Redact patterns: TOKEN, SECRET, PASSWORD, AUTH, API_KEY

### Sensitive Data Patterns

When logging or displaying data, redact matches for:
```regex
/(TOKEN|SECRET|PASSWORD|AUTH|API_KEY)/i
```

Replace sensitive values with `***REDACTED***`.

## Monorepo Workflow

### When to Work in Root
- Installing dependencies that affect multiple workspaces
- Building all packages: `npm run build`
- Running dev mode for multiple services

### When to Work in Workspace
- Workspace-specific scripts: `npm run build --workspace @codemantle/agent-daemon`
- Adding workspace-specific dependencies: `cd packages/agent-daemon && npm install <package>`

### Workspace Structure
```
packages/
  codemantle/          # CLI orchestrator (no build required)
  agent-daemon/        # Host daemon (TypeScript → pkg executables)
apps/
  control-plane/       # WebSocket server (TypeScript → Node.js)
  desktop-app/         # Tauri desktop app (React + Tauri)
```

## Packaging and Distribution

### Agent Daemon (pkg)
```bash
cd packages/agent-daemon
npm run build          # Compile TypeScript
npm run pkg            # Create executables (Linux, macOS, Windows)
```

Output: `dist/codemantle-agent-*` executables

### Desktop App (Tauri)
```bash
cd apps/desktop-app
npm run tauri:build    # Create platform-specific installers
```

Output: Platform-specific installers in `src-tauri/target/release/bundle/`

### CLI (npm)
No build step required. Uses Node.js directly via `#!/usr/bin/env node` shebang.

## Common Development Tasks

### Adding a New WebSocket Message Type

1. Add type definition in `packages/agent-daemon/src/contracts.ts` and `apps/control-plane/src/contracts.ts`
2. Update discriminated union types
3. Add handler in agent-daemon (`packages/agent-daemon/src/index.ts`)
4. Add handler in control-plane (`apps/control-plane/src/index.ts`)
5. Increment `WS_PROTOCOL_VERSION` if breaking change

### Debugging OpenCode Integration

1. Check session registry: `.opencode-session-registry.json`
2. Review plain text logs: `.opencode-session-log`
3. Parse structured logs: `.opencode-session-snapshot.jsonl`
4. Verify environment variables are set correctly
5. Test health endpoint: `curl http://localhost:<port>/health`
6. Check process is running: `ps aux | grep opencode`

### Testing OpenCode Locally

1. Set environment variables:
   ```bash
   export OPENCODE_COMMAND=/path/to/opencode
   export OPENCODE_HOST=127.0.0.1
   export OPENCODE_START_PORT=4096
   ```
2. Run agent-daemon in dev mode: `npm run dev:agent-daemon`
3. Trigger OpenCode start via WebSocket or HTTP API
4. Monitor logs for session URL extraction
5. Verify health checks pass within 15 seconds

---

**Last Updated:** 2026-03-02  
**For Questions:** Refer to inline documentation in `packages/agent-daemon/src/index.ts` (6500+ lines of OpenCode orchestration logic)
