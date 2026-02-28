# Control-plane bootstrap runbook

## Purpose

Initialize and validate `.env` for `@codemantle/panel` with secure defaults.

## Interactive first run

```bash
npx @codemantle/panel start
```

If `.env` is missing, you are prompted for ports, owner email/password, MFA, and cookie mode. The CLI writes `.env` and appends `.env` to `.gitignore`.

## Explicit init

```bash
npx @codemantle/panel init --env-file /opt/codemantle/.env
```

## Headless init

```bash
npx @codemantle/panel init --non-interactive --env-file /opt/codemantle/.env \
  --set AUTH_OWNER_EMAIL=owner@example.com \
  --set AUTH_OWNER_PASSWORD="replace-me" \
  --set VALID_TOKENS="replace-with-secure-token"
```

`AUTH_OWNER_PASSWORD` is converted to `AUTH_OWNER_PASSWORD_HASH` during generation.

## Validate env health

```bash
npx @codemantle/panel doctor --env-file /opt/codemantle/.env
```

## Migrate env schema

Preview migration output:

```bash
npx @codemantle/panel migrate-env --env-file /opt/codemantle/.env
```

Apply migration in place:

```bash
npx @codemantle/panel migrate-env --env-file /opt/codemantle/.env --write
```
