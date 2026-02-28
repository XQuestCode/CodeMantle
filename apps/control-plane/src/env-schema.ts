export const PANEL_ENV_SCHEMA_VERSION = 1;

export type EnvValidationIssue = {
  key: string;
  message: string;
};

const AUTH_MODES = new Set(["local", "disabled", "oidc"]);

export function validatePanelEnv(env: Record<string, string>): EnvValidationIssue[] {
  const issues: EnvValidationIssue[] = [];

  const schemaVersion = parseInteger(env.PANEL_ENV_SCHEMA_VERSION ?? "", PANEL_ENV_SCHEMA_VERSION);
  if (schemaVersion < PANEL_ENV_SCHEMA_VERSION) {
    issues.push({
      key: "PANEL_ENV_SCHEMA_VERSION",
      message: `schema version ${schemaVersion} is older than supported ${PANEL_ENV_SCHEMA_VERSION}`,
    });
  }

  if (!env.VALID_TOKENS?.trim()) {
    issues.push({ key: "VALID_TOKENS", message: "must be set" });
  }

  validatePort(env.CONTROL_PLANE_PORT, "CONTROL_PLANE_PORT", issues);
  validatePort(env.CONTROL_PLANE_API_PORT, "CONTROL_PLANE_API_PORT", issues);

  const authMode = (env.AUTH_MODE ?? "local").trim().toLowerCase();
  if (!AUTH_MODES.has(authMode)) {
    issues.push({ key: "AUTH_MODE", message: "must be one of local, disabled, oidc" });
  }

  if (authMode !== "disabled") {
    const email = (env.AUTH_OWNER_EMAIL ?? "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      issues.push({ key: "AUTH_OWNER_EMAIL", message: "must be a valid email" });
    }

    const hasPasswordHash = Boolean(env.AUTH_OWNER_PASSWORD_HASH?.trim());
    const hasPassword = Boolean(env.AUTH_OWNER_PASSWORD?.trim());
    if (!hasPasswordHash && !hasPassword) {
      issues.push({
        key: "AUTH_OWNER_PASSWORD_HASH",
        message: "set AUTH_OWNER_PASSWORD_HASH or AUTH_OWNER_PASSWORD",
      });
    }

    if (isTrue(env.AUTH_MFA_ENABLED ?? "false")) {
      const hasOwnerPasskey = Boolean(env.AUTH_OWNER_2FA_PASSKEY?.trim());
      const hasOwnerTotp = Boolean(env.AUTH_OWNER_TOTP_SECRET?.trim());
      const hasGlobalPasskey = Boolean(env.AUTH_MFA_PASSKEY?.trim());
      if (!hasOwnerPasskey && !hasOwnerTotp && !hasGlobalPasskey) {
        issues.push({
          key: "AUTH_OWNER_2FA_PASSKEY",
          message: "recommended when MFA is enabled",
        });
      }
    }
  }

  if (!env.JIT_CREDENTIAL_SIGNING_KEY?.trim()) {
    issues.push({ key: "JIT_CREDENTIAL_SIGNING_KEY", message: "must be set" });
  }

  return issues;
}

function validatePort(raw: string | undefined, key: string, issues: EnvValidationIssue[]): void {
  const parsed = parseInteger(raw ?? "", -1);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    issues.push({ key, message: "must be an integer between 1 and 65535" });
  }
}

function parseInteger(raw: string, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed)) {
    return fallback;
  }
  return parsed;
}

function isTrue(raw: string): boolean {
  const normalized = raw.trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes";
}
