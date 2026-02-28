# Changelog

All notable changes to this project are documented in this file.

## [0.1.2] - 2026-03-01

### Added

- Monorepo structure with `apps/control-plane`, `apps/desktop-app`, and `packages/agent-daemon`.
- Root docs set (`README`, architecture, deployment, security model, protocol pointer).
- OSS governance files (`CONTRIBUTING`, `SECURITY`, `CODE_OF_CONDUCT`, `LICENSE`).
- CI and component release workflows under `.github/workflows`.

### Changed

- Updated path-sensitive references to new monorepo layout.
- Desktop Tauri sidecar resource paths now resolve from `apps/desktop-app` to `packages/agent-daemon/bin`.
