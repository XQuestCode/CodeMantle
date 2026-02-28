# Contributing to CodeMantle

Thanks for contributing.

## Development setup

1. Install Node.js 20+ and npm 10+.
2. Install dependencies per component:

```bash
npm ci --prefix apps/control-plane
npm ci --prefix packages/agent-daemon
npm ci --prefix apps/desktop-app
```

3. Build all components before opening a PR:

```bash
npm run build --prefix apps/control-plane
npm run build --prefix packages/agent-daemon
npm run build --prefix apps/desktop-app
```

## Design constraints

- Keep protocol compatibility additive-first on `v=1`.
- Do not bypass daemon path/process security boundaries.
- Preserve milestone features (snapshot continuity, port proxy, centralized config push, JIT kill switch).
- Keep API changes backwards compatible unless explicitly versioned.

## Pull request guidance

- Keep PR scope focused and include test/build evidence.
- Update docs when contracts, env vars, deployment, or security behavior change.
- Call out any tenant boundary or authorization impact explicitly.

## Commit message style

- Use concise imperative messages.
- Prefer intent-focused phrasing (why) over implementation-only phrasing.

## Developer Certificate of Origin

By contributing, you certify that you have the right to submit your contribution under the repository license.
