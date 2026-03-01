# codemantle

[![npm version](https://img.shields.io/npm/v/codemantle?color=cb3837&logo=npm)](https://www.npmjs.com/package/codemantle)
[![npm downloads](https://img.shields.io/npm/dm/codemantle?color=blue)](https://www.npmjs.com/package/codemantle)
[![License](https://img.shields.io/github/license/XQuestCode/CodeMantle)](../../LICENSE)

Unified CodeMantle orchestrator CLI.

This package provides a single `codemantle` command that delegates to:

- `@codemantle/panel` (`codemantle-panel`)
- `@codemantle/agent-daemon` (`codemantle-agent`)

## Install

Install in a project:

```bash
npm install codemantle
```

Install globally:

```bash
npm install -g codemantle
```

Or run without installing globally:

```bash
npx codemantle --help
```

## Quick usage

Start panel flow:

```bash
codemantle --panel
```

Start agent setup flow:

```bash
codemantle --agent
```

## Commands

| Command                        | Description       | Default Behavior                 |
| ------------------------------ | ----------------- | -------------------------------- |
| `codemantle --panel [args...]` | Start panel       | `codemantle-panel start`         |
| `codemantle --agent [args...]` | Start agent       | `codemantle-agent --setup`       |
| `codemantle panel [args...]`   | Panel subcommand  | Pass-through to panel CLI        |
| `codemantle agent [args...]`   | Agent subcommand  | Pass-through to agent CLI        |
| `codemantle setup [target]`    | Interactive setup | `all` (panel init + agent setup) |

**Defaults explained:**

- `codemantle --panel` → `codemantle-panel start`
- `codemantle --agent` → `codemantle-agent --setup`
- `codemantle setup panel` → `codemantle-panel init`
- `codemantle setup agent` → `codemantle-agent --setup`
- `codemantle setup` → runs panel init first, then agent setup

## Examples

Initialize panel env in a specific path:

```bash
codemantle panel init --env-file /opt/codemantle/.env
```

Start panel with an explicit env file:

```bash
codemantle --panel --env-file /opt/codemantle/.env --non-interactive
```

Run agent directly:

```bash
codemantle agent
```

Run agent setup explicitly:

```bash
codemantle agent --setup
```

## Notes

- This package is an orchestrator wrapper; protocol/auth behavior is owned by panel and agent packages.
- Keep `@codemantle/panel` and `@codemantle/agent-daemon` versions aligned with this package version for predictable behavior.

## Related docs

- https://github.com/XQuestCode/codemantle/tree/main/apps/control-plane
- https://github.com/XQuestCode/codemantle/tree/main/packages/agent-daemon
- https://github.com/XQuestCode/codemantle/blob/main/docs/deployment.md
