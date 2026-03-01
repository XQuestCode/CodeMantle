import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { access, chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { parse as parseDotenv } from "dotenv";
import { hashPassword } from "./auth.js";
import { PANEL_ENV_SCHEMA_VERSION, type EnvValidationIssue, validatePanelEnv } from "./env-schema.js";

export type BootstrapOptions = {
  envFilePath: string;
  nonInteractive: boolean;
  yes: boolean;
  force: boolean;
  overrides: Record<string, string>;
};

export type BootstrapResult = {
  created: boolean;
  envFilePath: string;
  issues: EnvValidationIssue[];
};

const DEFAULTS: Record<string, string> = {
  PANEL_ENV_SCHEMA_VERSION: String(PANEL_ENV_SCHEMA_VERSION),
  CONTROL_PLANE_HOST: "127.0.0.1",
  CONTROL_PLANE_PORT: "8787",
  CONTROL_PLANE_API_PORT: "8788",
  HEARTBEAT_SECONDS: "25",
  REQUEST_TIMEOUT_MS: "15000",
  MAX_API_BODY_BYTES: "4096",
  MAX_PROMPT_CHARS: "8000",
  AUTH_MODE: "local",
  AUTH_MFA_ENABLED: "true",
  AUTH_MFA_PROVIDER: "authy",
  AUTH_MFA_REQUIRE_FOR_ALL_USERS: "false",
  AUTH_OWNER_ROLE: "owner",
  AUTH_SESSION_COOKIE_NAME: "cp_session",
  AUTH_CSRF_COOKIE_NAME: "cp_csrf",
  AUTH_COOKIE_SECURE: "true",
  AUTH_SESSION_TTL_MS: "43200000",
  AUTH_SESSION_IDLE_TIMEOUT_MS: "1800000",
  AUTH_LOGIN_MAX_ATTEMPTS: "6",
  AUTH_LOGIN_WINDOW_MS: "600000",
  AUTH_LOGIN_LOCKOUT_MS: "900000",
};

const OUTPUT_ORDER = [
  "PANEL_ENV_SCHEMA_VERSION",
  "VALID_TOKENS",
  "JIT_CREDENTIAL_SIGNING_KEY",
  "CONTROL_PLANE_HOST",
  "CONTROL_PLANE_PORT",
  "CONTROL_PLANE_API_PORT",
  "HEARTBEAT_SECONDS",
  "REQUEST_TIMEOUT_MS",
  "MAX_API_BODY_BYTES",
  "MAX_PROMPT_CHARS",
  "AUTH_MODE",
  "AUTH_MFA_ENABLED",
  "AUTH_MFA_PROVIDER",
  "AUTH_MFA_REQUIRE_FOR_ALL_USERS",
  "AUTH_OWNER_EMAIL",
  "AUTH_OWNER_PASSWORD_HASH",
  "AUTH_OWNER_ROLE",
  "AUTH_OWNER_2FA_PASSKEY",
  "AUTH_SESSION_COOKIE_NAME",
  "AUTH_CSRF_COOKIE_NAME",
  "AUTH_COOKIE_SECURE",
  "AUTH_SESSION_TTL_MS",
  "AUTH_SESSION_IDLE_TIMEOUT_MS",
  "AUTH_LOGIN_MAX_ATTEMPTS",
  "AUTH_LOGIN_WINDOW_MS",
  "AUTH_LOGIN_LOCKOUT_MS",
];

export async function envFileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function bootstrapEnvFile(options: BootstrapOptions): Promise<BootstrapResult> {
  const exists = await envFileExists(options.envFilePath);
  if (exists && !options.force) {
    const existing = await parseEnvFile(options.envFilePath);
    return {
      created: false,
      envFilePath: options.envFilePath,
      issues: validatePanelEnv(existing),
    };
  }

  const values = await resolveEnvValues(options);
  const issues = validatePanelEnv(values);
  if (issues.length > 0) {
    const rendered = issues.map((issue) => `${issue.key}: ${issue.message}`).join("\n");
    throw new Error(`env validation failed:\n${rendered}`);
  }

  await atomicWriteFile(options.envFilePath, serializeEnv(values));
  await appendGitIgnore(path.dirname(options.envFilePath), path.basename(options.envFilePath));

  return {
    created: true,
    envFilePath: options.envFilePath,
    issues,
  };
}

export async function migrateEnvFile(envFilePath: string, write: boolean): Promise<{ outputPath: string; changed: boolean; issues: EnvValidationIssue[] }> {
  const current = await parseEnvFile(envFilePath);
  const next = { ...DEFAULTS, ...current };

  next.PANEL_ENV_SCHEMA_VERSION = String(PANEL_ENV_SCHEMA_VERSION);
  next.VALID_TOKENS = current.VALID_TOKENS?.trim() || randomSecret(32);
  next.JIT_CREDENTIAL_SIGNING_KEY = current.JIT_CREDENTIAL_SIGNING_KEY?.trim() || randomSecret(32);
  next.AUTH_OWNER_EMAIL = (current.AUTH_OWNER_EMAIL ?? "").trim().toLowerCase();
  next.AUTH_MFA_ENABLED = normalizeBoolean(current.AUTH_MFA_ENABLED, DEFAULTS.AUTH_MFA_ENABLED ?? "true");
  next.AUTH_COOKIE_SECURE = normalizeBoolean(current.AUTH_COOKIE_SECURE, DEFAULTS.AUTH_COOKIE_SECURE ?? "true");

  if (!current.AUTH_OWNER_PASSWORD_HASH?.trim() && current.AUTH_OWNER_PASSWORD?.trim()) {
    next.AUTH_OWNER_PASSWORD_HASH = hashPassword(current.AUTH_OWNER_PASSWORD.trim());
  } else {
    next.AUTH_OWNER_PASSWORD_HASH = (current.AUTH_OWNER_PASSWORD_HASH ?? "").trim();
  }
  delete next.AUTH_OWNER_PASSWORD;

  if (!next.AUTH_OWNER_2FA_PASSKEY?.trim()) {
    next.AUTH_OWNER_2FA_PASSKEY = randomBase32Secret(20);
  }

  const outputPath = write ? envFilePath : `${envFilePath}.migrated`;
  const serialized = serializeEnv(next);
  const existingSerialized = (await readFile(envFilePath, "utf8")).replace(/\r\n/g, "\n");
  const changed = existingSerialized !== serialized;
  await atomicWriteFile(outputPath, serialized);

  return {
    outputPath,
    changed,
    issues: validatePanelEnv(next),
  };
}

export async function parseEnvFile(filePath: string): Promise<Record<string, string>> {
  const raw = await readFile(filePath, "utf8");
  const parsed = parseDotenv(raw);
  return parsed;
}

function normalizeBoolean(raw: string | undefined, fallback: string): string {
  if (!raw) {
    return fallback;
  }
  const normalized = raw.trim().toLowerCase();
  if (normalized === "1" || normalized === "true" || normalized === "yes") {
    return "true";
  }
  if (normalized === "0" || normalized === "false" || normalized === "no") {
    return "false";
  }
  return fallback;
}

function randomSecret(size: number): string {
  return randomBytes(size).toString("base64url");
}

function randomBase32Secret(size: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(size);
  let bits = "";
  for (const value of bytes) {
    bits += value.toString(2).padStart(8, "0");
  }
  let out = "";
  for (let index = 0; index < bits.length; index += 5) {
    const chunk = bits.slice(index, index + 5);
    if (chunk.length < 5) {
      break;
    }
    const numeric = Number.parseInt(chunk, 2);
    out += alphabet[numeric] ?? "A";
  }
  return out.slice(0, 32);
}

async function resolveEnvValues(options: BootstrapOptions): Promise<Record<string, string>> {
  const values: Record<string, string> = {
    ...DEFAULTS,
  };

  const mergedInput: Record<string, string> = {
    ...process.env,
    ...options.overrides,
  } as Record<string, string>;

  values.PANEL_ENV_SCHEMA_VERSION = String(PANEL_ENV_SCHEMA_VERSION);
  values.VALID_TOKENS = (mergedInput.VALID_TOKENS ?? "").trim() || randomSecret(32);
  values.JIT_CREDENTIAL_SIGNING_KEY = (mergedInput.JIT_CREDENTIAL_SIGNING_KEY ?? "").trim() || randomSecret(32);

  if (options.nonInteractive || options.yes || !(process.stdin.isTTY && process.stdout.isTTY)) {
    populateHeadlessValues(values, mergedInput);
    return values;
  }

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    values.CONTROL_PLANE_PORT = await promptValue(
      rl,
      "WebSocket port",
      mergedInput.CONTROL_PLANE_PORT ?? values.CONTROL_PLANE_PORT ?? DEFAULTS.CONTROL_PLANE_PORT ?? "8787",
    );
    values.CONTROL_PLANE_API_PORT = await promptValue(
      rl,
      "HTTP API port",
      mergedInput.CONTROL_PLANE_API_PORT ?? values.CONTROL_PLANE_API_PORT ?? DEFAULTS.CONTROL_PLANE_API_PORT ?? "8788",
    );
    values.AUTH_OWNER_EMAIL = (await promptValue(rl, "Owner email", mergedInput.AUTH_OWNER_EMAIL ?? "owner@example.com")).toLowerCase();

    const passwordHashInput = (mergedInput.AUTH_OWNER_PASSWORD_HASH ?? "").trim();
    if (passwordHashInput) {
      values.AUTH_OWNER_PASSWORD_HASH = passwordHashInput;
    } else {
      const password = await promptValue(rl, "Owner password (input is visible)", "", true);
      if (!password) {
        throw new Error("owner password is required");
      }
      values.AUTH_OWNER_PASSWORD_HASH = hashPassword(password);
    }

    const enableMfa = await promptBoolean(
      rl,
      "Enable MFA",
      normalizeBoolean(mergedInput.AUTH_MFA_ENABLED, values.AUTH_MFA_ENABLED ?? DEFAULTS.AUTH_MFA_ENABLED ?? "true") === "true",
    );
    values.AUTH_MFA_ENABLED = enableMfa ? "true" : "false";
    values.AUTH_COOKIE_SECURE = (
      await promptBoolean(
        rl,
        "Use secure cookies",
        normalizeBoolean(mergedInput.AUTH_COOKIE_SECURE, values.AUTH_COOKIE_SECURE ?? DEFAULTS.AUTH_COOKIE_SECURE ?? "true") === "true",
      )
    ) ? "true" : "false";
    values.AUTH_OWNER_2FA_PASSKEY = (mergedInput.AUTH_OWNER_2FA_PASSKEY ?? "").trim() || randomBase32Secret(20);
  } finally {
    rl.close();
  }

  return values;
}

function populateHeadlessValues(values: Record<string, string>, input: Record<string, string>): void {
  values.CONTROL_PLANE_PORT = (input.CONTROL_PLANE_PORT ?? values.CONTROL_PLANE_PORT ?? DEFAULTS.CONTROL_PLANE_PORT ?? "8787").trim();
  values.CONTROL_PLANE_API_PORT = (input.CONTROL_PLANE_API_PORT ?? values.CONTROL_PLANE_API_PORT ?? DEFAULTS.CONTROL_PLANE_API_PORT ?? "8788").trim();
  values.AUTH_OWNER_EMAIL = (input.AUTH_OWNER_EMAIL ?? "").trim().toLowerCase();
  values.AUTH_MFA_ENABLED = normalizeBoolean(input.AUTH_MFA_ENABLED, values.AUTH_MFA_ENABLED ?? DEFAULTS.AUTH_MFA_ENABLED ?? "true");
  values.AUTH_COOKIE_SECURE = normalizeBoolean(input.AUTH_COOKIE_SECURE, values.AUTH_COOKIE_SECURE ?? DEFAULTS.AUTH_COOKIE_SECURE ?? "true");
  values.AUTH_OWNER_2FA_PASSKEY = (input.AUTH_OWNER_2FA_PASSKEY ?? "").trim() || randomBase32Secret(20);

  const hash = (input.AUTH_OWNER_PASSWORD_HASH ?? "").trim();
  if (hash) {
    values.AUTH_OWNER_PASSWORD_HASH = hash;
    return;
  }

  const plain = (input.AUTH_OWNER_PASSWORD ?? "").trim();
  if (plain) {
    values.AUTH_OWNER_PASSWORD_HASH = hashPassword(plain);
  }
}

async function promptValue(
  rl: ReturnType<typeof createInterface>,
  label: string,
  fallback: string,
  allowEmpty = false,
): Promise<string> {
  const suffix = fallback ? ` [${fallback}]` : "";
  const raw = await rl.question(`${label}${suffix}: `);
  const answer = raw.trim();
  if (!answer && fallback) {
    return fallback;
  }
  if (!answer && !allowEmpty) {
    return promptValue(rl, label, fallback, allowEmpty);
  }
  return answer;
}

async function promptBoolean(rl: ReturnType<typeof createInterface>, label: string, fallback: boolean): Promise<boolean> {
  const marker = fallback ? "Y/n" : "y/N";
  const raw = await rl.question(`${label} (${marker}): `);
  const normalized = raw.trim().toLowerCase();
  if (!normalized) {
    return fallback;
  }
  if (normalized === "y" || normalized === "yes" || normalized === "true" || normalized === "1") {
    return true;
  }
  if (normalized === "n" || normalized === "no" || normalized === "false" || normalized === "0") {
    return false;
  }
  return promptBoolean(rl, label, fallback);
}

function serializeEnv(values: Record<string, string>): string {
  const lines: string[] = [];
  lines.push("# CodeMantle Panel configuration");
  lines.push("# Generated by codemantle-panel init");
  lines.push("");

  for (const key of OUTPUT_ORDER) {
    const value = values[key];
    if (!value) {
      continue;
    }
    lines.push(`${key}=${escapeValue(value)}`);
  }

  lines.push("");
  return `${lines.join("\n")}`;
}

function escapeValue(value: string): string {
  if (/^[A-Za-z0-9_./:@-]+$/.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

async function atomicWriteFile(filePath: string, content: string): Promise<void> {
  const directory = path.dirname(filePath);
  await mkdir(directory, { recursive: true });
  const tempPath = `${filePath}.tmp-${randomBytes(6).toString("hex")}`;
  await writeFile(tempPath, content, { encoding: "utf8", mode: 0o600 });
  await rename(tempPath, filePath);
  await chmod(filePath, 0o600).catch(() => {
  });
}

async function appendGitIgnore(directory: string, envFileName: string): Promise<void> {
  const gitIgnorePath = path.join(directory, ".gitignore");
  const targetEntry = envFileName === ".env" ? ".env" : envFileName;
  try {
    const current = await readFile(gitIgnorePath, "utf8");
    const normalized = current.replace(/\r\n/g, "\n");
    if (normalized.split("\n").includes(targetEntry)) {
      return;
    }
    const separator = normalized.endsWith("\n") ? "" : "\n";
    await writeFile(gitIgnorePath, `${normalized}${separator}${targetEntry}\n`, "utf8");
    return;
  } catch {
  }
  await writeFile(gitIgnorePath, `${targetEntry}\n`, "utf8");
}
