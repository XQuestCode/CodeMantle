# codemantle-desktop

Tauri desktop application for CodeMantle setup and local sidecar lifecycle.

## Scope

- First-run setup UX.
- Workspace selection and control-plane connection configuration.
- Launch and monitor packaged agent sidecar.

## Run

```bash
npm ci
npm run dev
```

Web build:

```bash
npm run build
```

Native Tauri build:

```bash
npm run tauri:build
```

## Release posture

This app is a first-class releasable artifact in CodeMantle and has dedicated desktop release workflow automation.

## Auto-updater

- Tauri updater plugin is enabled and checks for updates on startup plus a periodic background interval.
- Prompt mode (default) asks users before download/install; silent mode auto-installs in background.
- Configure mode with `VITE_CODEMANTLE_UPDATER_MODE=prompt|silent`.

Required Tauri updater config values (`src-tauri/tauri.conf.json`):

- `plugins.updater.endpoints`: HTTPS endpoint serving updater `latest.json`.
- `plugins.updater.pubkey`: public key paired with CI secret `TAURI_SIGNING_PRIVATE_KEY`.

Signing secrets used by release workflow are optional and guarded:

- Windows: `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD`
- macOS: `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`
- Updater signatures: `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
