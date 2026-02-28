import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export type AuthRole = "owner" | "admin" | "operator" | "viewer";

export type AuthMode = "local" | "disabled" | "oidc";

export type AuthMfaProvider = "totp" | "authy";

export type AuthUser = {
  subject: string;
  email: string;
  role: AuthRole;
  passwordHash: string;
  totpSecret?: string;
};

type LoginAttemptState = {
  count: number;
  windowStartedAt: number;
  lockedUntil?: number;
};

type SessionRecord = {
  id: string;
  subject: string;
  email: string;
  role: AuthRole;
  csrfToken: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
};

export type AuthSession = {
  id: string;
  subject: string;
  email: string;
  role: AuthRole;
  csrfToken: string;
};

export type AuthSecurityConfig = {
  mode: AuthMode;
  mfaEnabled: boolean;
  mfaProvider: AuthMfaProvider;
  mfaRequiredForAllUsers: boolean;
  sessionCookieName: string;
  csrfCookieName: string;
  secureCookies: boolean;
  sameSite: "Lax" | "Strict";
  sessionTtlMs: number;
  sessionIdleTimeoutMs: number;
  loginWindowMs: number;
  loginMaxAttempts: number;
  loginLockoutMs: number;
};

export type PasswordVerifyResult = {
  ok: boolean;
  needsRehash: boolean;
};

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;

const ROLE_ORDER: Record<AuthRole, number> = {
  viewer: 0,
  operator: 1,
  admin: 2,
  owner: 3,
};

export class AuthService {
  readonly config: AuthSecurityConfig;
  private readonly usersByEmail = new Map<string, AuthUser>();
  private readonly sessionsById = new Map<string, SessionRecord>();
  private readonly loginAttempts = new Map<string, LoginAttemptState>();

  constructor(config: AuthSecurityConfig, users: AuthUser[]) {
    this.config = config;
    for (const user of users) {
      this.usersByEmail.set(user.email.toLowerCase(), user);
    }
  }

  static fromEnv(env: NodeJS.ProcessEnv): AuthService {
    const mode = readAuthMode(env.AUTH_MODE);
    const mfaEnabled = readBoolean(env.AUTH_MFA_ENABLED, false);
    const mfaProvider = readMfaProvider(env.AUTH_MFA_PROVIDER);
    const config: AuthSecurityConfig = {
      mode,
      mfaEnabled,
      mfaProvider,
      mfaRequiredForAllUsers: readBoolean(env.AUTH_MFA_REQUIRE_FOR_ALL_USERS, mfaEnabled),
      sessionCookieName: env.AUTH_SESSION_COOKIE_NAME?.trim() || "cp_session",
      csrfCookieName: env.AUTH_CSRF_COOKIE_NAME?.trim() || "cp_csrf",
      secureCookies: readBoolean(env.AUTH_COOKIE_SECURE, env.NODE_ENV === "production"),
      sameSite: env.AUTH_COOKIE_SAMESITE === "Strict" ? "Strict" : "Lax",
      sessionTtlMs: readInt(env.AUTH_SESSION_TTL_MS, 12 * 60 * 60 * 1000, 5 * 60 * 1000, 7 * 24 * 60 * 60 * 1000),
      sessionIdleTimeoutMs: readInt(env.AUTH_SESSION_IDLE_TIMEOUT_MS, 30 * 60 * 1000, 60 * 1000, 24 * 60 * 60 * 1000),
      loginWindowMs: readInt(env.AUTH_LOGIN_WINDOW_MS, 10 * 60 * 1000, 60 * 1000, 24 * 60 * 60 * 1000),
      loginMaxAttempts: readInt(env.AUTH_LOGIN_MAX_ATTEMPTS, 6, 2, 100),
      loginLockoutMs: readInt(env.AUTH_LOGIN_LOCKOUT_MS, 15 * 60 * 1000, 60 * 1000, 24 * 60 * 60 * 1000),
    };

    const users = parseUsersFromEnv(env, mfaEnabled);
    return new AuthService(config, users);
  }

  roleAtLeast(actual: AuthRole, required: AuthRole): boolean {
    return ROLE_ORDER[actual] >= ROLE_ORDER[required];
  }

  getSession(cookies: Record<string, string>): AuthSession | null {
    if (this.config.mode === "disabled") {
      return {
        id: "disabled-auth",
        subject: "disabled-auth",
        email: "disabled-auth@local",
        role: "owner",
        csrfToken: "disabled-auth",
      };
    }

    const sessionId = cookies[this.config.sessionCookieName];
    if (!sessionId) {
      return null;
    }

    const session = this.sessionsById.get(sessionId);
    if (!session) {
      return null;
    }

    const now = Date.now();
    if (now >= session.expiresAt || now - session.lastSeenAt > this.config.sessionIdleTimeoutMs) {
      this.sessionsById.delete(session.id);
      return null;
    }
    session.lastSeenAt = now;
    return {
      id: session.id,
      subject: session.subject,
      email: session.email,
      role: session.role,
      csrfToken: session.csrfToken,
    };
  }

  login(
    email: string,
    password: string,
    totpCode: string,
    ipAddress: string,
  ): { ok: true; session: AuthSession } | { ok: false; error: "invalid_credentials" | "mfa_required" | "invalid_totp" | "mfa_not_configured" | "rate_limited" | "unsupported_auth_mode" } {
    if (this.config.mode === "oidc") {
      return { ok: false, error: "unsupported_auth_mode" };
    }
    if (this.config.mode === "disabled") {
      return { ok: false, error: "unsupported_auth_mode" };
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail || !password) {
      return { ok: false, error: "invalid_credentials" };
    }

    const rateLimitKey = `${ipAddress}:${normalizedEmail}`;
    const now = Date.now();
    const limiter = this.loginAttempts.get(rateLimitKey);
    if (limiter?.lockedUntil && limiter.lockedUntil > now) {
      return { ok: false, error: "rate_limited" };
    }

    const user = this.usersByEmail.get(normalizedEmail);
    if (!user) {
      this.recordFailedAttempt(rateLimitKey, now);
      return { ok: false, error: "invalid_credentials" };
    }

    const verify = verifyPasswordHash(password, user.passwordHash);
    if (!verify.ok) {
      this.recordFailedAttempt(rateLimitKey, now);
      return { ok: false, error: "invalid_credentials" };
    }

    const requiresMfa = this.config.mfaRequiredForAllUsers || Boolean(user.totpSecret);
    if (requiresMfa) {
      if (!user.totpSecret) {
        return { ok: false, error: "mfa_not_configured" };
      }
      const code = totpCode.trim();
      if (!code) {
        return { ok: false, error: "mfa_required" };
      }
      const validTotp = verifyTotpCode(user.totpSecret, code, now);
      if (!validTotp) {
        this.recordFailedAttempt(rateLimitKey, now);
        return { ok: false, error: "invalid_totp" };
      }
    }

    this.loginAttempts.delete(rateLimitKey);
    const session = this.createSession(user, now);
    return { ok: true, session };
  }

  logout(cookies: Record<string, string>): void {
    const sessionId = cookies[this.config.sessionCookieName];
    if (sessionId) {
      this.sessionsById.delete(sessionId);
    }
  }

  isCsrfValid(session: AuthSession, csrfHeaderValue: string | undefined, csrfCookieValue: string | undefined): boolean {
    if (this.config.mode === "disabled") {
      return true;
    }
    if (!csrfHeaderValue || !csrfCookieValue) {
      return false;
    }
    return secureEqual(session.csrfToken, csrfHeaderValue) && secureEqual(session.csrfToken, csrfCookieValue);
  }

  buildSetSessionCookies(session: AuthSession): string[] {
    if (this.config.mode === "disabled") {
      return [];
    }
    const cookieFlags = [
      "Path=/",
      `SameSite=${this.config.sameSite}`,
      `Max-Age=${Math.floor(this.config.sessionTtlMs / 1000)}`,
    ];
    const secure = this.config.secureCookies ? "; Secure" : "";
    return [
      `${this.config.sessionCookieName}=${session.id}; HttpOnly; ${cookieFlags.join("; ")}${secure}`,
      `${this.config.csrfCookieName}=${session.csrfToken}; ${cookieFlags.join("; ")}${secure}`,
    ];
  }

  buildClearSessionCookies(): string[] {
    if (this.config.mode === "disabled") {
      return [];
    }
    const base = "Path=/; Max-Age=0; SameSite=Lax";
    const secure = this.config.secureCookies ? "; Secure" : "";
    return [
      `${this.config.sessionCookieName}=; HttpOnly; ${base}${secure}`,
      `${this.config.csrfCookieName}=; ${base}${secure}`,
    ];
  }

  private recordFailedAttempt(key: string, now: number): void {
    const state = this.loginAttempts.get(key);
    if (!state || now - state.windowStartedAt > this.config.loginWindowMs) {
      this.loginAttempts.set(key, {
        count: 1,
        windowStartedAt: now,
      });
      return;
    }
    state.count += 1;
    if (state.count >= this.config.loginMaxAttempts) {
      state.lockedUntil = now + this.config.loginLockoutMs;
    }
  }

  private createSession(user: AuthUser, now: number): AuthSession {
    const id = randomToken(40);
    const csrfToken = randomToken(40);
    const record: SessionRecord = {
      id,
      subject: user.subject,
      email: user.email,
      role: user.role,
      csrfToken,
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + this.config.sessionTtlMs,
    };
    this.sessionsById.set(id, record);
    return {
      id,
      subject: user.subject,
      email: user.email,
      role: user.role,
      csrfToken,
    };
  }
}

export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) {
    return out;
  }
  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) {
      continue;
    }
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!key || !value) {
      continue;
    }
    out[key] = value;
  }
  return out;
}

function readAuthMode(value: string | undefined): AuthMode {
  if (value === "disabled" || value === "oidc" || value === "local") {
    return value;
  }
  return "local";
}

function parseUsersFromEnv(env: NodeJS.ProcessEnv, mfaEnabled: boolean): AuthUser[] {
  const users: AuthUser[] = [];
  const configured = env.AUTH_LOCAL_USERS?.trim();
  if (configured) {
    try {
      const parsed = JSON.parse(configured) as unknown;
      if (Array.isArray(parsed)) {
        for (const entry of parsed) {
          if (!isRecord(entry)) {
            continue;
          }
          const email = readEmail(entry.email);
          const role = readRole(entry.role);
          const subject = typeof entry.subject === "string" && entry.subject ? entry.subject : `local:${email}`;
          const totpSecret = resolveTotpSecret(
            typeof entry.totpSecret === "string" ? entry.totpSecret : undefined,
            typeof entry.mfaPasskey === "string" ? entry.mfaPasskey : undefined,
            typeof entry.authyPasskey === "string" ? entry.authyPasskey : undefined,
          );
          const passwordHash = resolvePasswordHash(entry.passwordHash, entry.password);
          if (!email || !role || !passwordHash) {
            continue;
          }
          users.push({
            subject,
            email,
            role,
            passwordHash,
            ...((totpSecret || mfaEnabled) ? { totpSecret: totpSecret ?? "" } : {}),
          });
        }
      }
    } catch {
      // ignored
    }
  }

  const ownerEmail = readEmail(env.AUTH_OWNER_EMAIL);
  const ownerPassword = env.AUTH_OWNER_PASSWORD?.trim();
  const ownerHash = env.AUTH_OWNER_PASSWORD_HASH?.trim();
  if (ownerEmail && (ownerPassword || ownerHash) && !users.some((user) => user.email.toLowerCase() === ownerEmail.toLowerCase())) {
    const passwordHash = ownerHash || hashPassword(ownerPassword ?? "");
    const totpSecret = resolveTotpSecret(
      env.AUTH_OWNER_TOTP_SECRET,
      env.AUTH_OWNER_2FA_PASSKEY,
      env.AUTH_OWNER_AUTHY_PASSKEY,
      env.AUTH_MFA_PASSKEY,
    );
    users.push({
      subject: `local:${ownerEmail}`,
      email: ownerEmail,
      role: readRole(env.AUTH_OWNER_ROLE) ?? "owner",
      passwordHash,
      ...((totpSecret || mfaEnabled) ? { totpSecret: totpSecret ?? "" } : {}),
    });
  }

  return users;
}

function resolvePasswordHash(passwordHash: unknown, password: unknown): string {
  if (typeof passwordHash === "string" && passwordHash.trim()) {
    return passwordHash.trim();
  }
  if (typeof password === "string" && password.trim()) {
    return hashPassword(password.trim());
  }
  return "";
}

function readEmail(value: unknown): string {
  if (typeof value !== "string") {
    return "";
  }
  const normalized = value.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)) {
    return "";
  }
  return normalized;
}

function readRole(value: unknown): AuthRole | null {
  if (value === "owner" || value === "admin" || value === "operator" || value === "viewer") {
    return value;
  }
  return null;
}

function readInt(raw: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isInteger(parsed)) {
    return fallback;
  }
  if (parsed < min) {
    return min;
  }
  if (parsed > max) {
    return max;
  }
  return parsed;
}

function readBoolean(raw: string | undefined, fallback: boolean): boolean {
  if (!raw) {
    return fallback;
  }
  const normalized = raw.trim().toLowerCase();
  if (normalized === "1" || normalized === "true" || normalized === "yes") {
    return true;
  }
  if (normalized === "0" || normalized === "false" || normalized === "no") {
    return false;
  }
  return fallback;
}

function readMfaProvider(raw: string | undefined): AuthMfaProvider {
  const normalized = raw?.trim().toLowerCase();
  if (normalized === "authy" || normalized === "totp") {
    return normalized;
  }
  return "totp";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function randomToken(length: number): string {
  return randomBytes(length).toString("base64url").slice(0, length);
}

function secureEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return timingSafeEqual(leftBuffer, rightBuffer);
}

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("base64url");
  const key = scryptSync(password, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 128 * 1024 * 1024,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt}$${key.toString("base64url")}`;
}

function verifyPasswordHash(password: string, encodedHash: string): PasswordVerifyResult {
  const parts = encodedHash.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") {
    return { ok: false, needsRehash: false };
  }
  const n = Number.parseInt(parts[1] ?? "", 10);
  const r = Number.parseInt(parts[2] ?? "", 10);
  const p = Number.parseInt(parts[3] ?? "", 10);
  const salt = parts[4] ?? "";
  const expected = parts[5] ?? "";
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p) || !salt || !expected) {
    return { ok: false, needsRehash: false };
  }
  const derived = scryptSync(password, salt, SCRYPT_KEYLEN, {
    N: n,
    r,
    p,
    maxmem: 128 * 1024 * 1024,
  }).toString("base64url");
  const ok = secureEqual(derived, expected);
  const needsRehash = ok && (n !== SCRYPT_N || r !== SCRYPT_R || p !== SCRYPT_P);
  return { ok, needsRehash };
}

function normalizeTotpSecret(raw: string): string {
  return raw.replace(/\s+/g, "").toUpperCase();
}

function resolveTotpSecret(...candidates: Array<string | undefined>): string | undefined {
  for (const candidate of candidates) {
    if (!candidate || !candidate.trim()) {
      continue;
    }
    return normalizeTotpSecret(candidate);
  }
  return undefined;
}

function verifyTotpCode(secretBase32: string, code: string, now: number): boolean {
  if (!/^\d{6}$/.test(code)) {
    return false;
  }
  const secret = decodeBase32(secretBase32);
  if (!secret || secret.length === 0) {
    return false;
  }
  const currentStep = Math.floor(now / 30000);
  for (let drift = -1; drift <= 1; drift += 1) {
    const candidate = generateHotp(secret, currentStep + drift);
    if (secureEqual(candidate, code)) {
      return true;
    }
  }
  return false;
}

function decodeBase32(value: string): Buffer | null {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const normalized = value.replace(/=+$/g, "").toUpperCase();
  for (const char of normalized) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      return null;
    }
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateHotp(secret: Buffer, counter: number): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuffer.writeUInt32BE(counter >>> 0, 4);
  const digest = createHmac("sha1", secret).update(counterBuffer).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = (
    ((digest[offset]! & 0x7f) << 24)
    | ((digest[offset + 1]! & 0xff) << 16)
    | ((digest[offset + 2]! & 0xff) << 8)
    | (digest[offset + 3]! & 0xff)
  ) >>> 0;
  return (binary % 1_000_000).toString().padStart(6, "0");
}
