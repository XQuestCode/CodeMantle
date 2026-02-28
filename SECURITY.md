# Security policy

## Reporting vulnerabilities

Please do not open public issues for sensitive vulnerabilities.

- Email: `security@codemantle.dev`
- Include: affected component, impact, reproduction steps, and suggested fix if available.

We will acknowledge receipt as quickly as possible and coordinate a responsible disclosure timeline.

## Supported surfaces

Security-relevant components:

- `apps/control-plane`
- `packages/agent-daemon`
- `apps/desktop-app`

## Hard requirements

- Preserve `v=1` protocol compatibility unless explicitly versioned.
- Keep daemon-enforced filesystem and process boundaries intact.
- Never introduce plaintext secret logging.
- Keep auth and tenant checks ahead of tunnel dispatch.

## Secret handling

- Never commit real tokens or credentials.
- Use environment variables and `.env.example` for placeholders only.
- Rotate compromised tokens immediately.
