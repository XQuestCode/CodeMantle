# Control-plane npm operations runbook

## Install

```bash
npm install -g @codemantle/panel
```

Or run directly with `npx`.

## Start

```bash
codemantle-panel start --env-file /opt/codemantle/.env --non-interactive
```

## PM2 baseline

```bash
pm2 start "codemantle-panel start --env-file /opt/codemantle/.env --non-interactive" --name codemantle-panel
pm2 save
pm2 startup
```

Common PM2 operations:

```bash
pm2 status
pm2 logs codemantle-panel
pm2 restart codemantle-panel
pm2 stop codemantle-panel
```

## Upgrade

```bash
npm install -g @codemantle/panel@latest
codemantle-panel migrate-env --env-file /opt/codemantle/.env --write
pm2 restart codemantle-panel
```

## Rollback

```bash
npm install -g @codemantle/panel@<previous-version>
pm2 restart codemantle-panel
```

## Troubleshooting

- `auth_required` loops on login: verify `AUTH_COOKIE_SECURE` and proxy HTTPS forwarding.
- startup failure with missing `.env`: run `codemantle-panel init --env-file ...`.
- daemon auth failures: verify `VALID_TOKENS` contains the expected token and restart panel.
