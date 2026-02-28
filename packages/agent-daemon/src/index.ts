import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { realpathSync } from "node:fs";
import { appendFile, chmod, lstat, mkdir, opendir, readFile, realpath, rename, rmdir, stat, unlink, writeFile } from "node:fs/promises";
import net from "node:net";
import { config as loadDotenv, parse as parseDotenv } from "dotenv";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import WebSocket, { type RawData } from "ws";
import {
  MAX_DIRECTORY_LIMIT,
  MAX_STREAM_CHUNK_BYTES,
  WS_PROTOCOL_VERSION,
  type DirectoryEntry,
  type DirectoryRequestMessage,
  type ErrorCode,
  type ErrorMessage,
  type HandshakeAckMessage,
  type HandshakeInitMessage,
  type MkdirRequestMessage,
  type MkdirResponseMessage,
  type RenameRequestMessage,
  type RenameResponseMessage,
  type RmdirRequestMessage,
  type RmdirResponseMessage,
  type SetupSaveRequestMessage,
  type SetupSaveResponseMessage,
  type ConfigCheckPushRequestMessage,
  type ConfigViewResponseMessage,
  type SetupStatusRequestMessage,
  type SetupStatusResponseMessage,
  type SessionStatusRequestMessage,
  type SessionStatusResponseMessage,
  type SessionLogRequestMessage,
  type SessionJitCredential,
  type JitKillSwitchRequestMessage,
  type JitKillSwitchResponseMessage,
  type SessionResultMessage,
  type PortListMessage,
  type PortProxyRequestMessage,
  type PortProxyResponseMessage,
  type ProxyHeaderEntry,
  type StartSessionMessage,
  type TelemetryPingMessage,
  type TerminateSessionMessage,
  type GitStatusRequestMessage,
  type GitStatusResponseMessage,
  type GitInitRequestMessage,
  type GitInitResponseMessage,
  type GitCloneRequestMessage,
  type GitCloneResponseMessage,
  type GitAddRequestMessage,
  type GitAddResponseMessage,
  type GitCommitRequestMessage,
  type GitCommitResponseMessage,
  type GitPushRequestMessage,
  type GitPushResponseMessage,
  type GitPullRequestMessage,
  type GitPullResponseMessage,
  type GitBranchRequestMessage,
  type GitBranchResponseMessage,
  type GitCheckoutRequestMessage,
  type GitCheckoutResponseMessage,
  type GitConfigRequestMessage,
  type GitConfigResponseMessage,
  type GitLogMessage,
} from "./contracts.js";
import { Provisioner, type DependencyStatus, type SetupProgressEvent } from "./provisioner.js";

loadDotenv();

let CONTROL_PLANE_URL = "";
let AGENT_AUTH_TOKEN = "";
const OPENCODE_BASE_URL = (process.env.OPENCODE_BASE_URL ?? "http://localhost:4096").replace(/\/$/, "");
const OPENCODE_PROVIDER_ID = process.env.OPENCODE_PROVIDER_ID ?? "openai";
const OPENCODE_MODEL_ID = process.env.OPENCODE_MODEL_ID ?? "gpt-5.3-codex";
const OPENCODE_HOST = process.env.OPENCODE_HOST ?? "127.0.0.1";
const OPENCODE_START_PORT = parseInt(process.env.OPENCODE_START_PORT ?? "4096", 10);
const OPENCODE_PORT_SCAN_RANGE = parseInt(process.env.OPENCODE_PORT_SCAN_RANGE ?? "200", 10);
const OPENCODE_BOOT_TIMEOUT_MS = parseInt(process.env.OPENCODE_BOOT_TIMEOUT_MS ?? "15000", 10);
const OPENCODE_READY_CHECK_MS = parseInt(process.env.OPENCODE_READY_CHECK_MS ?? "250", 10);
const OPENCODE_COMMAND = process.env.OPENCODE_COMMAND ?? "opencode";
const AGENT_VERSION = process.env.AGENT_VERSION ?? "0.1.0";
const DEVICE_ID = process.env.DEVICE_ID ?? defaultDeviceId();

const BASE_RECONNECT_MS = parseInt(process.env.RECONNECT_BASE_MS ?? "1000", 10);
const MAX_RECONNECT_MS = parseInt(process.env.RECONNECT_MAX_MS ?? "30000", 10);
const MAX_FRAME_BYTES = parseInt(process.env.MAX_FRAME_BYTES ?? String(MAX_STREAM_CHUNK_BYTES + 1024), 10);
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS ?? "10000", 10);
const GIT_COMMAND_TIMEOUT_MS = parseInt(process.env.GIT_COMMAND_TIMEOUT_MS ?? "120000", 10);
const GIT_LOG_MAX_LINES = parseInt(process.env.GIT_LOG_MAX_LINES ?? "200", 10);
const SESSION_LOG_REPLAY_LINES = parseInt(process.env.SESSION_LOG_REPLAY_LINES ?? "50", 10);
const SESSION_LOG_REPLAY_MAX_LINES = parseInt(process.env.SESSION_LOG_REPLAY_MAX_LINES ?? "200", 10);
const SESSION_LOG_MAX_BYTES = parseInt(process.env.SESSION_LOG_MAX_BYTES ?? "1048576", 10);
const SESSION_SNAPSHOT_MAX_BYTES = parseInt(process.env.SESSION_SNAPSHOT_MAX_BYTES ?? "5242880", 10);
const SESSION_JIT_MAX_TTL_MS = parseInt(process.env.SESSION_JIT_MAX_TTL_MS ?? "3600000", 10);
const SESSION_JIT_MIN_TTL_MS = parseInt(process.env.SESSION_JIT_MIN_TTL_MS ?? "15000", 10);
const SESSION_JIT_DEFAULT_ENV_VAR = process.env.SESSION_JIT_DEFAULT_ENV_VAR ?? "OPENCODE_SESSION_TOKEN";
const SESSION_JIT_ENV_MAX_PAIRS = parseInt(process.env.SESSION_JIT_ENV_MAX_PAIRS ?? "8", 10);
const SESSION_JIT_ENV_MAX_VALUE_BYTES = parseInt(process.env.SESSION_JIT_ENV_MAX_VALUE_BYTES ?? "2048", 10);
const SESSION_JIT_ENV_ALLOWLIST = parseJitEnvAllowlist(
  process.env.SESSION_JIT_ENV_ALLOWLIST
    ?? `${SESSION_JIT_DEFAULT_ENV_VAR},OPENCODE_JIT_SCOPE,OPENCODE_JIT_TOKEN_EXPIRES_AT`,
);
const PORT_SCAN_INTERVAL_MS = parseInt(process.env.PORT_SCAN_INTERVAL_MS ?? "3000", 10);
const PORT_SCAN_MAX_REPORTED = parseInt(process.env.PORT_SCAN_MAX_REPORTED ?? "24", 10);
const PORT_SCAN_MIN_PORT = parseInt(process.env.PORT_SCAN_MIN_PORT ?? "3000", 10);
const PORT_SCAN_MAX_PORT = parseInt(process.env.PORT_SCAN_MAX_PORT ?? "8000", 10);
const PORT_PROXY_TIMEOUT_MS = parseInt(process.env.PORT_PROXY_TIMEOUT_MS ?? "20000", 10);
const PORT_PROXY_MAX_RESPONSE_BYTES = parseInt(process.env.PORT_PROXY_MAX_RESPONSE_BYTES ?? "1048576", 10);
const CONFIG_PUSH_MAX_BYTES = parseInt(process.env.CONFIG_PUSH_MAX_BYTES ?? "262144", 10);
const CONFIG_RESTRICTED_DEFAULT_APPLY_PATH = path.join(".opencode", "opencode.json");

const ALLOWED_PROJECT_ROOT = path.resolve(process.env.AGENT_PROJECT_ROOT ?? process.cwd());
const ALLOWED_PROJECT_ROOT_REAL = resolveRootRealPath(ALLOWED_PROJECT_ROOT);
const ENV_FILE_PATH = path.join(ALLOWED_PROJECT_ROOT_REAL, ".env");
const SESSION_LOG_FILE = path.join(ALLOWED_PROJECT_ROOT_REAL, ".opencode-session-log");
const SESSION_SNAPSHOT_FILE = path.join(ALLOWED_PROJECT_ROOT_REAL, ".opencode-session-snapshot.jsonl");
const OPENCODE_REGISTRY_FILE = process.env.OPENCODE_REGISTRY_FILE ?? path.join(ALLOWED_PROJECT_ROOT_REAL, ".opencode-session-registry.json");
const OPENCODE_CONFIG_ALLOWLIST = parseConfigAllowlist(process.env.OPENCODE_CONFIG_ALLOWLIST ?? ".opencode/opencode.json");
const DAEMON_LOCK_FILE = process.env.AGENT_LOCK_FILE ?? path.join(os.tmpdir(), "codemantle-agent-daemon.lock.json");
const TELEMETRY_ACTIVE_HANDLES_ENABLED = process.env.TELEMETRY_ACTIVE_HANDLES === "1";
const SESSION_URL_LOG_REGEX = /\bhttps?:\/\/(?:127\.0\.0\.1|localhost):\d+\/[A-Za-z0-9_-]+\/session\b/;
let opencodeOrchestrator: OpenCodeOrchestrator | null = null;
let daemonLockHeld = false;

let socket: WebSocket | null = null;
let reconnectAttempt = 0;
let reconnectTimer: NodeJS.Timeout | null = null;
let telemetryTimer: NodeJS.Timeout | null = null;
let watchdogTimer: NodeJS.Timeout | null = null;
let portScanTimer: NodeJS.Timeout | null = null;
let lastActivityAt = 0;
let activeH1Nonce = "";
let heartbeatSeconds = 25;
let handshakeComplete = false;
let stopping = false;
const runtimeSensitiveValues = new Set<string>();
const baselineListeningPorts = new Set<number>();
const publishedListeningPorts = new Set<number>();
let baselinePortsInitialized = false;
let latestSessionInitConfig: {
  templateId: string;
  templateVersion: string;
  digest: string;
  receivedAt: number;
  providers: string[];
  mcpTools: Array<{ alias: string; status: "disabled" | "ask" | "allow" }>;
} | null = null;

function connect(): void {
  if (stopping) {
    return;
  }

  clearTimer(reconnectTimer);
  reconnectTimer = null;

  log(`connecting to ${CONTROL_PLANE_URL}`);
  const ws = new WebSocket(CONTROL_PLANE_URL, {
    perMessageDeflate: false,
    maxPayload: MAX_FRAME_BYTES,
    handshakeTimeout: 10000,
  });
  socket = ws;

  ws.on("open", () => {
    reconnectAttempt = 0;
    handshakeComplete = false;
    lastActivityAt = Date.now();

    const h1 = buildHandshakeInit();
    activeH1Nonce = h1.n;
    sendJson(ws, h1);

    log(`connected, sent handshake device=${DEVICE_ID} root=${ALLOWED_PROJECT_ROOT_REAL}`);
  });

  ws.on("message", (raw) => {
    lastActivityAt = Date.now();
    handleIncomingMessage(ws, raw);
  });

  ws.on("ping", () => {
    lastActivityAt = Date.now();
  });

  ws.on("pong", () => {
    lastActivityAt = Date.now();
  });

  ws.on("close", (code, reason) => {
    clearLifecycleTimers();
    handshakeComplete = false;
    socket = null;
    log(`disconnected code=${code} reason=${reason.toString("utf8") || "n/a"}`);
    scheduleReconnect();
  });

  ws.on("error", (error) => {
    log(`socket error: ${error.message}`);
  });
}

function handleIncomingMessage(ws: WebSocket, raw: RawData): void {
  const payload = decodeJson(raw);
  if (payload === null) {
    log("received invalid json payload");
    ws.close(1002, "invalid json");
    return;
  }

  const ack = parseHandshakeAck(payload);
  if (ack && !handshakeComplete) {
    if (!verifyHandshakeAck(ack)) {
      log("handshake ack signature validation failed");
      ws.close(1008, "invalid ack");
      return;
    }

    handshakeComplete = true;
    heartbeatSeconds = ack.hb;
    log(`handshake complete sid=${ack.s} hb=${ack.hb}s mx=${ack.mx}`);
    if (opencodeOrchestrator) {
      void opencodeOrchestrator.handleControlPlaneReconnect();
    }
    sendTelemetryPing();
    startTelemetryLoop();
    startWatchdogLoop();
    startPortScanLoop();
    return;
  }

  const errorMessage = parseErrorMessage(payload);
  if (errorMessage) {
    const detail = errorMessage.m ? ` (${errorMessage.m})` : "";
    log(`control-plane error: ${errorMessage.c}${detail}`);
    if (errorMessage.c === "AUTH") {
      ws.close(1008, "auth failed");
    }
    if (errorMessage.c === "UPDATE_REQUIRED") {
      ws.close(1008, "update required");
    }
    return;
  }

  if (!handshakeComplete) {
    return;
  }

  const directoryRequest = parseDirectoryRequest(payload);
  if (directoryRequest) {
    void handleDirectoryRequest(directoryRequest);
    return;
  }

  const startSessionRequest = parseStartSession(payload);
  if (startSessionRequest) {
    void handleSessionStart(startSessionRequest);
    return;
  }

  const sessionStatusRequest = parseSessionStatusRequest(payload);
  if (sessionStatusRequest) {
    void handleSessionStatus(sessionStatusRequest);
    return;
  }

  const sessionLogRequest = parseSessionLogRequest(payload);
  if (sessionLogRequest) {
    void handleSessionLogRequest(sessionLogRequest);
    return;
  }

  const portProxyRequest = parsePortProxyRequest(payload);
  if (portProxyRequest) {
    void handlePortProxyRequest(portProxyRequest);
    return;
  }

  const setupStatusRequest = parseSetupStatusRequest(payload);
  if (setupStatusRequest) {
    void handleSetupStatus(setupStatusRequest);
    return;
  }

  const setupSaveRequest = parseSetupSaveRequest(payload);
  if (setupSaveRequest) {
    void handleSetupSave(setupSaveRequest);
    return;
  }

  const configPushRequest = parseConfigCheckRequest(payload);
  if (configPushRequest) {
    void handleConfigPush(configPushRequest);
    return;
  }

  const killSwitchRequest = parseJitKillSwitchRequest(payload);
  if (killSwitchRequest) {
    void handleJitKillSwitch(killSwitchRequest);
    return;
  }

  const terminateSessionRequest = parseTerminateSession(payload);
  if (terminateSessionRequest) {
    void handleSessionTerminate(terminateSessionRequest);
    return;
  }

  const mkdirRequest = parseMkdirRequest(payload);
  if (mkdirRequest) {
    void handleMkdir(mkdirRequest);
    return;
  }

  const rmdirRequest = parseRmdirRequest(payload);
  if (rmdirRequest) {
    void handleRmdir(rmdirRequest);
    return;
  }

  const renameRequest = parseRenameRequest(payload);
  if (renameRequest) {
    void handleRename(renameRequest);
    return;
  }

  // Git Request Handlers
  const gitStatusRequest = parseGitStatusRequest(payload);
  if (gitStatusRequest) {
    void handleGitStatus(gitStatusRequest);
    return;
  }

  const gitInitRequest = parseGitInitRequest(payload);
  if (gitInitRequest) {
    void handleGitInit(gitInitRequest);
    return;
  }

  const gitCloneRequest = parseGitCloneRequest(payload);
  if (gitCloneRequest) {
    void handleGitClone(gitCloneRequest);
    return;
  }

  const gitAddRequest = parseGitAddRequest(payload);
  if (gitAddRequest) {
    void handleGitAdd(gitAddRequest);
    return;
  }

  const gitCommitRequest = parseGitCommitRequest(payload);
  if (gitCommitRequest) {
    void handleGitCommit(gitCommitRequest);
    return;
  }

  const gitPushRequest = parseGitPushRequest(payload);
  if (gitPushRequest) {
    void handleGitPush(gitPushRequest);
    return;
  }

  const gitPullRequest = parseGitPullRequest(payload);
  if (gitPullRequest) {
    void handleGitPull(gitPullRequest);
    return;
  }

  const gitBranchRequest = parseGitBranchRequest(payload);
  if (gitBranchRequest) {
    void handleGitBranch(gitBranchRequest);
    return;
  }

  const gitCheckoutRequest = parseGitCheckoutRequest(payload);
  if (gitCheckoutRequest) {
    void handleGitCheckout(gitCheckoutRequest);
    return;
  }

  const gitConfigRequest = parseGitConfigRequest(payload);
  if (gitConfigRequest) {
    void handleGitConfig(gitConfigRequest);
    return;
  }
}

function buildHandshakeInit(): HandshakeInitMessage {
  const nonce = randomToken(20);
  const ts = Date.now();
  const hostname = os.hostname();
  const platform = os.platform();
  const authKeyId = deriveAuthKeyId(AGENT_AUTH_TOKEN);
  return {
    v: WS_PROTOCOL_VERSION,
    t: "h1",
    d: DEVICE_ID,
    ak: authKeyId,
    n: nonce,
    ts,
    m: sign(AGENT_AUTH_TOKEN, canonicalH1ForKeyId(DEVICE_ID, nonce, ts, authKeyId)),
    c: telemetryFingerprint(hostname, platform, AGENT_VERSION),
    hn: hostname.slice(0, 64),
    os: platform.slice(0, 64),
    av: AGENT_VERSION.slice(0, 32),
  };
}

function verifyHandshakeAck(message: HandshakeAckMessage): boolean {
  const expected = sign(AGENT_AUTH_TOKEN, `h2|1|${message.s}|${message.n}|${message.hb}|${message.mx}|${activeH1Nonce}`);
  return secureEqual(message.m, expected);
}

function sendTelemetryPing(): void {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN || !handshakeComplete) {
    return;
  }

  const activeHandles = TELEMETRY_ACTIVE_HANDLES_ENABLED
    ? (process as { _getActiveHandles?: () => unknown[] })._getActiveHandles?.().length ?? 0
    : 0;

  const ping: TelemetryPingMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "p",
    u: clampUint32(Math.floor(process.uptime())),
    r: clampUint32(process.memoryUsage().rss),
    a: clampInt(activeHandles, 0, 65535),
  };
  sendJson(ws, ping);
}

function startTelemetryLoop(): void {
  clearTimer(telemetryTimer);
  telemetryTimer = setInterval(() => {
    sendTelemetryPing();
  }, Math.max(5, heartbeatSeconds) * 1000);
  telemetryTimer.unref();
}

function startWatchdogLoop(): void {
  clearTimer(watchdogTimer);
  watchdogTimer = setInterval(() => {
    const ws = socket;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return;
    }
    const timeoutMs = Math.max(15000, heartbeatSeconds * 3000);
    if (Date.now() - lastActivityAt > timeoutMs) {
      log("heartbeat timeout, terminating socket");
      ws.terminate();
    }
  }, Math.max(5, heartbeatSeconds) * 1000);
  watchdogTimer.unref();
}

function startPortScanLoop(): void {
  clearTimer(portScanTimer);
  publishedListeningPorts.clear();
  void refreshPortExposure();
  portScanTimer = setInterval(() => {
    void refreshPortExposure();
  }, Math.max(1500, PORT_SCAN_INTERVAL_MS));
  portScanTimer.unref();
}

async function refreshPortExposure(): Promise<void> {
  if (!handshakeComplete) {
    return;
  }

  if (!opencodeOrchestrator?.hasActiveSessions()) {
    publishExposedPorts([]);
    return;
  }

  const listeningPorts = await detectListeningPorts();

  if (!baselinePortsInitialized) {
    baselinePortsInitialized = true;
    for (const port of listeningPorts) {
      baselineListeningPorts.add(port);
    }
    publishExposedPorts([]);
    return;
  }

  if (listeningPorts.length === 0) {
    publishExposedPorts([]);
    return;
  }

  const nextExposed = listeningPorts
    .filter((port) => !baselineListeningPorts.has(port))
    .filter((port) => !opencodeOrchestrator?.isManagedOpenCodePort(port))
    .sort((left, right) => left - right)
    .slice(0, PORT_SCAN_MAX_REPORTED);

  publishExposedPorts(nextExposed);
}

function publishExposedPorts(ports: number[]): void {
  const normalized = Array.from(new Set(ports)).sort((left, right) => left - right);
  const previous = Array.from(publishedListeningPorts).sort((left, right) => left - right);
  if (normalized.length === previous.length && normalized.every((port, index) => port === previous[index])) {
    return;
  }

  publishedListeningPorts.clear();
  for (const port of normalized) {
    publishedListeningPorts.add(port);
  }

  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const payload: PortListMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "pl",
    p: normalized,
  };
  sendJson(ws, payload);
}

function scheduleReconnect(): void {
  if (stopping || reconnectTimer) {
    return;
  }

  const backoff = Math.min(MAX_RECONNECT_MS, BASE_RECONNECT_MS * 2 ** reconnectAttempt);
  const jitter = Math.floor(Math.random() * 300);
  const delay = backoff + jitter;
  reconnectAttempt += 1;

  log(`reconnecting in ${delay}ms (attempt ${reconnectAttempt})`);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, delay);
  reconnectTimer.unref();
}

async function handleDirectoryRequest(message: DirectoryRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    const stat = await lstat(targetRealPath);
    if (!stat.isDirectory()) {
      sendError(ws, "PATH", message.i);
      return;
    }

    const limit = clampInt(message.l, 1, MAX_DIRECTORY_LIMIT);
    const entries = await listDirectoryEntries(targetRealPath, limit);
    sendJson(ws, {
      v: WS_PROTOCOL_VERSION,
      t: "ds",
      i: message.i,
      k: message.k,
      e: entries,
    });
  } catch (error) {
    const code = mapFsError(error);
    sendError(ws, code, message.i);
  }
}

async function listDirectoryEntries(directoryPath: string, limit: number): Promise<DirectoryEntry[]> {
  const entries: DirectoryEntry[] = [];
  const dir = await opendir(directoryPath);
  try {
    for await (const dirent of dir) {
      if (entries.length >= limit) {
        break;
      }
      if (!isSafeEntryName(dirent.name)) {
        continue;
      }

      const entryPath = path.join(directoryPath, dirent.name);
      const stat = await lstat(entryPath);
      if (stat.isSymbolicLink()) {
        continue;
      }
      if (stat.isDirectory()) {
        entries.push(["d", dirent.name, 0]);
        continue;
      }
      if (stat.isFile()) {
        entries.push(["f", dirent.name, clampUint32(stat.size), clampUint32(Math.floor(stat.mtimeMs))]);
      }
    }
  } finally {
    try {
      await dir.close();
    } catch {
    }
  }

  return entries;
}

async function handleSessionStart(message: StartSessionMessage): Promise<void> {
  if (!opencodeOrchestrator) {
    sendSessionResult(message, false, "daemon_not_ready");
    return;
  }

  if (message.j?.t) {
    runtimeSensitiveValues.add(message.j.t);
  }
  appendContinuityLog("session", `start session=${message.s}`);
  const folderPath = message.p ?? ".";
  const result = await opencodeOrchestrator.initSession(message.s, folderPath, message.j);
  sendSessionResult(message, result.ok, result.message, result.sessionId, result.uiUrl);
  if (result.ok) {
    void refreshPortExposure();
  }
}

async function handleSessionStatus(message: SessionStatusRequestMessage): Promise<void> {
  if (!opencodeOrchestrator) {
    const ws = socket;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return;
    }
    sendJson(ws, { v: WS_PROTOCOL_VERSION, t: "sv", i: message.i, o: 0, m: "daemon_not_ready" });
    return;
  }
  const status = await opencodeOrchestrator.getSessionStatus(message.p);
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const response: SessionStatusResponseMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "sv",
    i: message.i,
    o: status.ok ? 1 : 0,
    ...(status.port ? { p: status.port } : {}),
    ...(status.pid ? { d: status.pid } : {}),
    ...(status.sessionUrl ? { u: status.sessionUrl } : {}),
    ...(status.message ? { m: status.message } : {}),
  };
  sendJson(ws, response);
}

async function handleSessionLogRequest(message: SessionLogRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  if (!opencodeOrchestrator) {
    sendError(ws, "INTERNAL", message.i);
    return;
  }

  const requestedLines = clampInt(message.l, 1, SESSION_LOG_REPLAY_MAX_LINES);
  const lines = await opencodeOrchestrator.readSessionLogTailLines(requestedLines);
  const replayText = lines.join("\n");
  const chunks = chunkTextForStream(replayText, MAX_STREAM_CHUNK_BYTES);
  for (let index = 0; index < chunks.length; index += 1) {
    sendJson(ws, {
      v: WS_PROTOCOL_VERSION,
      t: "sc",
      x: message.x,
      q: index,
      e: index === chunks.length - 1 ? 1 : 0,
      d: chunks[index],
    });
  }
}

async function handlePortProxyRequest(message: PortProxyRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  if (!publishedListeningPorts.has(message.p)) {
    const denied: PortProxyResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "pv",
      i: message.i,
      o: 0,
      m: "port_not_exposed",
    };
    sendJson(ws, denied);
    return;
  }

  try {
    const relativePath = message.u.startsWith("/") ? message.u : `/${message.u}`;
    const targetUrl = `http://127.0.0.1:${message.p}${relativePath}`;
    const headers = new Headers();
    for (const [name, value] of message.h) {
      if (!isAllowedProxyRequestHeader(name)) {
        continue;
      }
      headers.set(name, value);
    }

    const hasBody = typeof message.b === "string" && message.b.length > 0;
    const bodyBuffer = hasBody ? Buffer.from(message.b!, "base64") : undefined;
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, PORT_PROXY_TIMEOUT_MS);
    timeout.unref();

    let responseBody = Buffer.alloc(0);
    let responseStatus = 502;
    let responseStatusText = "proxy_error";
    let responseHeaders: ProxyHeaderEntry[] = [];

    try {
      const response = await fetch(targetUrl, {
        method: message.m,
        headers,
        ...(bodyBuffer ? { body: bodyBuffer } : {}),
        redirect: "manual",
        signal: controller.signal,
      });
      responseStatus = response.status;
      responseStatusText = response.statusText || "ok";
      responseHeaders = toProxyHeaderEntries(response.headers);
      const arrayBuffer = await response.arrayBuffer();
      responseBody = Buffer.from(arrayBuffer);
    } finally {
      clearTimeout(timeout);
    }

    if (responseBody.byteLength > PORT_PROXY_MAX_RESPONSE_BYTES) {
      const payload: PortProxyResponseMessage = {
        v: WS_PROTOCOL_VERSION,
        t: "pv",
        i: message.i,
        o: 0,
        m: "proxy_response_too_large",
      };
      sendJson(ws, payload);
      return;
    }

    const payload: PortProxyResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "pv",
      i: message.i,
      o: 1,
      sc: responseStatus,
      sm: responseStatusText,
      h: responseHeaders,
      b: responseBody.length > 0 ? responseBody.toString("base64") : "",
    };
    sendJson(ws, payload);
  } catch (error) {
    const messageText = error instanceof Error ? error.message : "proxy_failed";
    const payload: PortProxyResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "pv",
      i: message.i,
      o: 0,
      m: truncateText(singleLine(messageText), 240),
    };
    sendJson(ws, payload);
  }
}

async function handleSetupStatus(message: SetupStatusRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const status = await readSetupStatusSnapshot();
  const response: SetupStatusResponseMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "cg",
    i: message.i,
    o: status.ok ? 1 : 0,
    ...(status.configured !== undefined ? { c: status.configured ? 1 : 0 } : {}),
    ...(status.controlPlaneUrl ? { u: status.controlPlaneUrl } : {}),
    ...(status.hasAgentAuthToken !== undefined ? { a: status.hasAgentAuthToken ? 1 : 0 } : {}),
    ...(status.opencodeCommand ? { oc: status.opencodeCommand } : {}),
    ...(status.opencodeHost ? { oh: status.opencodeHost } : {}),
    ...(status.opencodeStartPort ? { os: status.opencodeStartPort } : {}),
    ...(status.opencodeProviderId ? { op: status.opencodeProviderId } : {}),
    ...(status.opencodeModelId ? { om: status.opencodeModelId } : {}),
    ...(status.requestTimeoutMs ? { rt: status.requestTimeoutMs } : {}),
    ...(status.message ? { m: status.message } : {}),
  };
  sendJson(ws, response);
}

async function handleSetupSave(message: SetupSaveRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const result = await writeSetupConfig(message);
  const response: SetupSaveResponseMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "cv",
    i: message.i,
    o: result.ok ? 1 : 0,
    ...(result.message ? { m: result.message } : {}),
  };
  sendJson(ws, response);
}

async function handleConfigPush(message: ConfigCheckPushRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const result = await validateAndApplyConfigPush(message);
  const response: ConfigViewResponseMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "cv",
    i: message.i,
    k: "cfg",
    ...(message.ph ? { ph: message.ph } : {}),
    ...(message.sc ? { sc: message.sc } : {}),
    o: result.ok ? 1 : 0,
    tid: message.tid,
    tv: message.tv,
    st: result.ok ? "applied" : "rejected",
    pd: result.digest,
    at: result.appliedAt,
    ...(result.appliedPath ? { ap: result.appliedPath } : {}),
    ...(result.violations.length > 0 ? { vd: result.violations } : {}),
    ...(message.alg ? { alg: message.alg } : {}),
    ...(message.sg ? { sg: message.sg } : {}),
    ...(message.pm ? { pm: message.pm } : {}),
    ...(result.message ? { m: result.message } : {}),
  };
  sendJson(ws, response);
}

async function validateAndApplyConfigPush(message: ConfigCheckPushRequestMessage): Promise<{
  ok: boolean;
  digest: string;
  appliedAt: number;
  appliedPath?: string;
  violations: string[];
  message?: string;
}> {
  const violations: string[] = [];
  const computedDigest = computeCanonicalDigest(message.cfg);
  const now = Date.now();
  const policyMode = message.pm ?? "off";
  const phase = message.ph ?? "runtime";
  const scope = message.sc ?? (phase === "session-init" ? "session-init" : "full");

  if (computedDigest !== message.pd) {
    violations.push("digest_mismatch");
  }

  const safeApplyPath = sanitizeConfigApplyPath(message.ap);
  if (!safeApplyPath) {
    violations.push("invalid_apply_path");
  } else if (!OPENCODE_CONFIG_ALLOWLIST.has(safeApplyPath)) {
    violations.push("apply_path_not_allowlisted");
  }

  const canonical = toCanonicalJson(message.cfg);
  if (Buffer.byteLength(canonical, "utf8") > CONFIG_PUSH_MAX_BYTES) {
    violations.push("config_payload_too_large");
  }

  const declaredPolicyMode = readDeclaredPolicyMode(message.cfg);
  if (declaredPolicyMode && declaredPolicyMode !== policyMode) {
    violations.push("policy_mode_mismatch");
  }
  if (policyMode === "restricted") {
    if (!safeApplyPath || safeApplyPath !== CONFIG_RESTRICTED_DEFAULT_APPLY_PATH) {
      violations.push("restricted_policy_path_violation");
    }
    if (!message.alg || !message.sg) {
      violations.push("restricted_policy_signature_required");
    }
  }

  if (phase === "session-init" && scope !== "session-init") {
    violations.push("session_init_scope_mismatch");
  }
  if (phase === "runtime" && scope !== "full") {
    violations.push("runtime_scope_mismatch");
  }

  if (safeApplyPath) {
    const pathValidation = await validateConfigApplyPathBoundary(safeApplyPath, phase === "runtime");
    violations.push(...pathValidation.violations);
  }

  if (phase === "session-init") {
    validateSessionInitConfig(message.cfg, violations);
  }

  if (violations.length > 0) {
    return {
      ok: false,
      digest: computedDigest,
      appliedAt: now,
      violations,
      message: "config_rejected",
    };
  }

  const relativeApplyPath = safeApplyPath!;

  if (phase === "session-init") {
    const providers = readSessionInitProviders(message.cfg);
    const mcpTools = readSessionInitMcpTools(message.cfg);
    latestSessionInitConfig = {
      templateId: message.tid,
      templateVersion: message.tv,
      digest: computedDigest,
      receivedAt: now,
      providers,
      mcpTools,
    };
    appendContinuityLog("session", `session-init config accepted template=${message.tid}@${message.tv} digest=${computedDigest}`);
    return {
      ok: true,
      digest: computedDigest,
      appliedAt: Date.now(),
      appliedPath: relativeApplyPath,
      violations: [],
      message: "config_session_init_applied",
    };
  }

  const absoluteTargetPath = path.resolve(ALLOWED_PROJECT_ROOT_REAL, relativeApplyPath);
  const absoluteParentPath = path.dirname(absoluteTargetPath);

  try {
    await mkdir(absoluteParentPath, { recursive: true });
    const rootRealPath = await realpath(ALLOWED_PROJECT_ROOT_REAL);
    const parentRealPath = await realpath(absoluteParentPath);
    if (!isPathWithinRoot(rootRealPath, parentRealPath)) {
      return {
        ok: false,
        digest: computedDigest,
        appliedAt: now,
        violations: ["apply_path_escape"],
        message: "config_rejected",
      };
    }

    const existing = await lstat(absoluteTargetPath).catch(() => null);
    if (existing?.isSymbolicLink()) {
      return {
        ok: false,
        digest: computedDigest,
        appliedAt: now,
        violations: ["apply_path_symlink_not_allowed"],
        message: "config_rejected",
      };
    }

    await atomicWriteJson(absoluteTargetPath, canonical);
    appendContinuityLog("session", `config applied template=${message.tid}@${message.tv} digest=${computedDigest}`);
    return {
      ok: true,
      digest: computedDigest,
      appliedAt: Date.now(),
      appliedPath: relativeApplyPath,
      violations: [],
      message: "config_applied",
    };
  } catch {
    return {
      ok: false,
      digest: computedDigest,
      appliedAt: Date.now(),
      violations: ["write_failed"],
      message: "config_apply_failed",
    };
  }
}

async function validateConfigApplyPathBoundary(relativeApplyPath: string, ensureParent: boolean): Promise<{ violations: string[] }> {
  const violations: string[] = [];
  const absoluteTargetPath = path.resolve(ALLOWED_PROJECT_ROOT_REAL, relativeApplyPath);
  const absoluteParentPath = path.dirname(absoluteTargetPath);

  if (!isPathWithinRoot(ALLOWED_PROJECT_ROOT_REAL, absoluteTargetPath)) {
    violations.push("apply_path_escape");
    return { violations };
  }

  try {
    if (ensureParent) {
      await mkdir(absoluteParentPath, { recursive: true });
    }

    const rootRealPath = await realpath(ALLOWED_PROJECT_ROOT_REAL);
    const parentStat = await lstat(absoluteParentPath).catch(() => null);
    if (parentStat) {
      const parentRealPath = await realpath(absoluteParentPath);
      if (!isPathWithinRoot(rootRealPath, parentRealPath)) {
        violations.push("apply_path_escape");
      }
    }

    const existing = await lstat(absoluteTargetPath).catch(() => null);
    if (existing?.isSymbolicLink()) {
      violations.push("apply_path_symlink_not_allowed");
    }
  } catch {
    violations.push("apply_path_validation_failed");
  }

  return { violations };
}

function validateSessionInitConfig(config: Record<string, unknown>, violations: string[]): void {
  if (!hasOnlyKeys(config, ["codenucleus"])) {
    violations.push("session_init_scope_violation");
    return;
  }
  if (!isObject(config.codenucleus)) {
    violations.push("session_init_missing_codenucleus");
    return;
  }

  const codenucleus = config.codenucleus;
  if (!hasOnlyKeys(codenucleus, ["schemaVersion", "templateId", "templateVersion", "phase", "scope", "policy", "sessionInit"])) {
    violations.push("session_init_codenucleus_unknown_fields");
  }
  if (codenucleus.phase !== "session-init") {
    violations.push("session_init_phase_invalid");
  }
  if (codenucleus.scope !== "session-init") {
    violations.push("session_init_scope_invalid");
  }
  if (!isObject(codenucleus.sessionInit)) {
    violations.push("session_init_payload_missing");
    return;
  }

  const payload = codenucleus.sessionInit;
  if (!hasOnlyKeys(payload, ["providers", "routing", "mcp"])) {
    violations.push("session_init_payload_unknown_fields");
  }
  if (!Array.isArray(payload.providers)) {
    violations.push("session_init_providers_invalid");
  } else {
    for (const provider of payload.providers) {
      if (!matches(provider, /^[a-z0-9][a-z0-9_-]{1,63}$/)) {
        violations.push("session_init_provider_invalid");
        break;
      }
    }
  }

  if (!isObject(payload.mcp) || !hasOnlyKeys(payload.mcp, ["tools"]) || !Array.isArray(payload.mcp.tools)) {
    violations.push("session_init_mcp_invalid");
  } else {
    for (const tool of payload.mcp.tools) {
      if (!isObject(tool) || !hasOnlyKeys(tool, ["alias", "serverId", "version", "type", "status"])) {
        violations.push("session_init_mcp_scope_violation");
        break;
      }
      if (!matches(tool.alias, /^[a-z0-9][a-z0-9_-]{1,63}$/)) {
        violations.push("session_init_mcp_alias_invalid");
      }
      if (!matches(tool.serverId, /^[a-z0-9][a-z0-9_-]{1,63}$/)) {
        violations.push("session_init_mcp_server_invalid");
      }
      if (!matches(tool.version, /^[A-Za-z0-9._-]{1,32}$/)) {
        violations.push("session_init_mcp_version_invalid");
      }
      if (tool.type !== "remote") {
        violations.push("session_init_mcp_type_invalid");
      }
      if (tool.status !== "disabled" && tool.status !== "ask" && tool.status !== "allow") {
        violations.push("session_init_mcp_status_invalid");
      }
    }
  }

  if (!isObject(payload.routing)) {
    violations.push("session_init_routing_invalid");
  }

  const forbidden = collectForbiddenFieldPaths(config, new Set(["url", "urls", "header", "headers", "command", "commands", "executable", "exec", "env", "secret", "secrets", "token", "tokens", "runtime"]));
  for (const pathText of forbidden) {
    violations.push(`forbidden_field:${pathText}`);
  }
}

function readSessionInitProviders(config: Record<string, unknown>): string[] {
  if (!isObject(config.codenucleus) || !isObject(config.codenucleus.sessionInit) || !Array.isArray(config.codenucleus.sessionInit.providers)) {
    return [];
  }
  return config.codenucleus.sessionInit.providers.filter((entry): entry is string => typeof entry === "string").slice(0, 64);
}

function readSessionInitMcpTools(config: Record<string, unknown>): Array<{ alias: string; status: "disabled" | "ask" | "allow" }> {
  if (!isObject(config.codenucleus) || !isObject(config.codenucleus.sessionInit) || !isObject(config.codenucleus.sessionInit.mcp)) {
    return [];
  }
  const tools = config.codenucleus.sessionInit.mcp.tools;
  if (!Array.isArray(tools)) {
    return [];
  }
  const out: Array<{ alias: string; status: "disabled" | "ask" | "allow" }> = [];
  for (const tool of tools) {
    if (!isObject(tool) || typeof tool.alias !== "string") {
      continue;
    }
    const status = tool.status;
    if (status !== "disabled" && status !== "ask" && status !== "allow") {
      continue;
    }
    out.push({ alias: tool.alias, status });
  }
  return out.slice(0, 128);
}

function collectForbiddenFieldPaths(value: unknown, forbiddenKeys: Set<string>, pathPrefix = "cfg"): string[] {
  if (Array.isArray(value)) {
    const out: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      out.push(...collectForbiddenFieldPaths(value[index], forbiddenKeys, `${pathPrefix}[${index}]`));
    }
    return out;
  }
  if (!isObject(value)) {
    return [];
  }

  const out: string[] = [];
  for (const [key, nested] of Object.entries(value)) {
    if (forbiddenKeys.has(key.toLowerCase())) {
      out.push(`${pathPrefix}.${key}`);
    }
    out.push(...collectForbiddenFieldPaths(nested, forbiddenKeys, `${pathPrefix}.${key}`));
  }
  return out;
}

async function atomicWriteJson(targetPath: string, canonicalJson: string): Promise<void> {
  const tempPath = `${targetPath}.tmp-${randomToken(8)}`;
  const body = `${canonicalJson}\n`;
  await writeFile(tempPath, body, { encoding: "utf8", mode: 0o600 });
  try {
    await rename(tempPath, targetPath);
  } catch {
    await unlink(targetPath).catch(() => {
    });
    await rename(tempPath, targetPath);
  }
  await chmod(targetPath, 0o600).catch(() => {
  });
}

async function handleSessionTerminate(message: TerminateSessionMessage): Promise<void> {
  if (!opencodeOrchestrator) {
    sendSessionResult(message, false, "daemon_not_ready");
    return;
  }
  appendContinuityLog("session", `terminate session=${message.s}`);
  const result = await opencodeOrchestrator.terminateSession(message.s);
  if (!opencodeOrchestrator.hasActiveSessions()) {
    publishExposedPorts([]);
  }
  sendSessionResult(message, result.ok, result.message);
}

async function handleJitKillSwitch(message: JitKillSwitchRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  if (!opencodeOrchestrator) {
    const response: JitKillSwitchResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "jv",
      i: message.i,
      o: 0,
      a: 0,
      m: "daemon_not_ready",
    };
    sendJson(ws, response);
    return;
  }

  try {
    const affected = await opencodeOrchestrator.revokeJitCredentials({
      ...(message.s ? { sessionId: message.s } : {}),
      ...(message.r ? { credentialRef: message.r } : {}),
      reason: message.m ?? "kill_switch",
    });

    const response: JitKillSwitchResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "jv",
      i: message.i,
      o: 1,
      a: clampUint32(affected),
    };
    sendJson(ws, response);

    if (message.x === 1) {
      setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.close(1011, "kill_switch");
        }
      }, 10).unref();
    }
  } catch {
    const response: JitKillSwitchResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "jv",
      i: message.i,
      o: 0,
      a: 0,
      m: "kill_switch_failed",
    };
    sendJson(ws, response);
  }
}

function sendSessionResult(
  message: StartSessionMessage | TerminateSessionMessage,
  ok: boolean,
  reason?: string,
  sessionId?: string,
  uiUrl?: string,
): void {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }
  const response: SessionResultMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "sr",
    i: message.i,
    s: sessionId ?? message.s,
    o: ok ? 1 : 0,
    ...(reason ? { m: reason } : {}),
    ...(uiUrl ? { u: uiUrl } : {}),
  };
  sendJson(ws, response);
}

function resolveRootAlias(alias: string): string | null {
  if (alias === "cwd") {
    return ALLOWED_PROJECT_ROOT_REAL;
  }
  return null;
}

function sanitizeRelativePath(input: string): string | null {
  if (typeof input !== "string" || input.length > 512 || input.includes("\0")) {
    return null;
  }
  const normalized = input.replace(/\\/g, "/").trim();
  if (normalized === "" || normalized === "." || normalized === "/") {
    return ".";
  }

  const withoutDotPrefix = normalized.startsWith("./") ? normalized.slice(2) : normalized;
  if (withoutDotPrefix === "") {
    return ".";
  }
  if (withoutDotPrefix.startsWith("/") || withoutDotPrefix.startsWith("\\") || /^[A-Za-z]:/.test(withoutDotPrefix)) {
    return null;
  }

  const segments = withoutDotPrefix.split("/");
  const safeSegments: string[] = [];
  for (const segment of segments) {
    if (!segment || segment === "." || segment === "..") {
      return null;
    }
    if (segment.length > 255 || segment.includes(":")) {
      return null;
    }
    safeSegments.push(segment);
  }
  if (safeSegments.length === 0) {
    return ".";
  }
  return safeSegments.join(path.sep);
}

function parseConfigAllowlist(raw: string): Set<string> {
  const allowlist = new Set<string>();
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }
    const normalized = sanitizeConfigApplyPath(trimmed);
    if (normalized) {
      allowlist.add(normalized);
    }
  }
  if (allowlist.size === 0) {
    allowlist.add(path.join(".opencode", "opencode.json"));
  }
  return allowlist;
}

function parseJitEnvAllowlist(raw: string): Set<string> {
  const allowlist = new Set<string>();
  for (const part of raw.split(",")) {
    const key = part.trim();
    if (!isJitEnvVarName(key)) {
      continue;
    }
    allowlist.add(key);
  }
  allowlist.add(SESSION_JIT_DEFAULT_ENV_VAR);
  allowlist.add("OPENCODE_JIT_TOKEN_EXPIRES_AT");
  allowlist.add("OPENCODE_JIT_SCOPE");
  return allowlist;
}

function isJitEnvVarName(value: string): boolean {
  return /^[A-Z_][A-Z0-9_]{1,63}$/.test(value);
}

function isJitAllowedEnvVarName(value: string): boolean {
  return isJitEnvVarName(value) && SESSION_JIT_ENV_ALLOWLIST.has(value);
}

function isValidJitEnvPairs(value: unknown): value is Array<[string, string]> {
  if (!Array.isArray(value) || value.length > SESSION_JIT_ENV_MAX_PAIRS) {
    return false;
  }
  const seen = new Set<string>();
  for (const entry of value) {
    if (!Array.isArray(entry) || entry.length !== 2) {
      return false;
    }
    const [name, rawValue] = entry;
    if (typeof name !== "string" || !isJitAllowedEnvVarName(name)) {
      return false;
    }
    if (seen.has(name)) {
      return false;
    }
    seen.add(name);
    if (typeof rawValue !== "string" || rawValue.length === 0 || rawValue.includes("\0")) {
      return false;
    }
    if (Buffer.byteLength(rawValue, "utf8") > SESSION_JIT_ENV_MAX_VALUE_BYTES) {
      return false;
    }
  }
  return true;
}

function sanitizeConfigApplyPath(input: string): string | null {
  const safe = sanitizeRelativePath(input);
  if (!safe) {
    return null;
  }
  if (!safe.endsWith(".json")) {
    return null;
  }
  return safe;
}

function toCanonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function computeCanonicalDigest(value: unknown): string {
  return createHash("sha256").update(toCanonicalJson(value)).digest("base64url");
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => sortValue(entry));
  }
  if (isObject(value)) {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort((left, right) => left.localeCompare(right))) {
      sorted[key] = sortValue(value[key]);
    }
    return sorted;
  }
  return value;
}

function isPathWithinRoot(rootPath: string, targetPath: string): boolean {
  const relative = path.relative(rootPath, targetPath);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function isSafeEntryName(name: string): boolean {
  if (!name || name.length > 255) {
    return false;
  }
  return !name.includes("/") && !name.includes("\\") && !name.includes("\0");
}

function mapFsError(error: unknown): ErrorCode {
  if (error && typeof error === "object" && "code" in error) {
    const code = String((error as { code: unknown }).code);
    if (code === "ENOENT" || code === "ENOTDIR") {
      return "PATH";
    }
    if (code === "EACCES" || code === "EPERM") {
      return "ROOT";
    }
  }
  return "INTERNAL";
}

function decodeJson(raw: RawData): unknown | null {
  const text = decodeText(raw);
  if (text === null || text.length > MAX_FRAME_BYTES) {
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function decodeText(raw: RawData): string | null {
  if (typeof raw === "string") {
    return raw;
  }
  if (raw instanceof Buffer) {
    return raw.toString("utf8");
  }
  if (Array.isArray(raw)) {
    return Buffer.concat(raw).toString("utf8");
  }
  if (raw instanceof ArrayBuffer) {
    return Buffer.from(raw).toString("utf8");
  }
  return null;
}

function parseHandshakeAck(value: unknown): HandshakeAckMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "s", "n", "hb", "mx", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "h2") {
    return null;
  }
  if (!matches(value.s, /^[A-Za-z0-9_-]{12,32}$/)) {
    return null;
  }
  if (!matches(value.n, /^[A-Za-z0-9_-]{16,24}$/)) {
    return null;
  }
  if (!isInteger(value.hb) || value.hb < 5 || value.hb > 120) {
    return null;
  }
  if (!isInteger(value.mx) || value.mx < 256 || value.mx > 8192) {
    return null;
  }
  if (!matches(value.m, /^[A-Za-z0-9_-]{43}$/)) {
    return null;
  }
  return value as unknown as HandshakeAckMessage;
}

async function handleMkdir(message: MkdirRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(path.dirname(targetPath));
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    await mkdir(targetPath, { recursive: true });
    const response: MkdirResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "mr",
      i: message.i,
      o: 1,
    };
    sendJson(ws, response);
  } catch (error) {
    const code = mapFsError(error);
    sendError(ws, code, message.i);
  }
}

async function handleRmdir(message: RmdirRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    await rmdir(targetPath);
    const response: RmdirResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "rr",
      i: message.i,
      o: 1,
    };
    sendJson(ws, response);
  } catch (error) {
    const code = mapFsError(error);
    sendError(ws, code, message.i);
  }
}

async function handleRename(message: RenameRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safeSourcePath = sanitizeRelativePath(message.s);
  const safeDestPath = sanitizeRelativePath(message.d);
  if (!safeSourcePath || !safeDestPath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const sourcePath = path.resolve(rootPath, safeSourcePath);
  const destPath = path.resolve(rootPath, safeDestPath);

  try {
    const rootRealPath = await realpath(rootPath);
    const sourceRealPath = await realpath(sourcePath);
    const destDirPath = await realpath(path.dirname(destPath));
    
    if (!isPathWithinRoot(rootRealPath, sourceRealPath) || !isPathWithinRoot(rootRealPath, destDirPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    await rename(sourcePath, destPath);
    const response: RenameResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "rp",
      i: message.i,
      o: 1,
    };
    sendJson(ws, response);
  } catch (error) {
    const code = mapFsError(error);
    sendError(ws, code, message.i);
  }
}

// Git Handlers
async function handleGitStatus(message: GitStatusRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    // Execute git status
    const result = await execGitCommand(targetPath, ["status", "--porcelain", "-b"], message.i);
    const lines = result.stdout.split("\n").filter(line => line.length > 0);
    
    const branchLine = lines.find(line => line.startsWith("##"));
    const branch = branchLine ? branchLine.replace("## ", "").split("...")[0] : "unknown";
    
    const added: string[] = [];
    const modified: string[] = [];
    const untracked: string[] = [];
    const deleted: string[] = [];
    
    for (const line of lines) {
      if (line.startsWith("##")) continue;
      const status = line.substring(0, 2);
      const filename = line.substring(3);
      
      if (status.includes("A")) added.push(filename);
      else if (status.includes("M")) modified.push(filename);
      else if (status.includes("?")) untracked.push(filename);
      else if (status.includes("D")) deleted.push(filename);
    }

    const response: GitStatusResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gt",
      i: message.i,
      o: 1,
      b: branch || "unknown",
      a: added,
      m: modified,
      u: untracked,
      d: deleted,
    };
    sendJson(ws, response);
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_status_failed");
    const response: GitStatusResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gt",
      i: message.i,
      o: 0,
      e: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function handleGitInit(message: GitInitRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    await mkdir(targetPath, { recursive: true });
    const targetRealPath = await realpath(targetPath);
    
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    const result = await execGitCommand(targetPath, ["init"], message.i);
    
    const response: GitInitResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gj",
      i: message.i,
      o: 1,
      ...(result.summary ? { m: result.summary } : {}),
    };
    sendJson(ws, response);
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_init_failed");
    const response: GitInitResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gj",
      i: message.i,
      o: 0,
      m: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function handleGitClone(message: GitCloneRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const repoUrl = message.u.trim();
  if (!repoUrl) {
    const response: GitCloneResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gl",
      i: message.i,
      o: 0,
      m: "Repository URL is required",
    };
    sendJson(ws, response);
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  try {
    const rootRealPath = await realpath(rootPath);
    const targetPath = path.resolve(rootPath, safePath);
    if (!isPathWithinRoot(rootRealPath, targetPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    let cloneCwd = rootRealPath;
    let cloneDestination: string | undefined;

    try {
      const targetRealPath = await realpath(targetPath);
      if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
        sendError(ws, "ROOT", message.i);
        return;
      }
      const targetStat = await lstat(targetRealPath);
      if (!targetStat.isDirectory()) {
        sendError(ws, "PATH", message.i);
        return;
      }
      cloneCwd = targetRealPath;
      cloneDestination = ".";
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error
        ? String((error as { code: unknown }).code)
        : "";
      if (code !== "ENOENT" && code !== "ENOTDIR") {
        throw error;
      }

      const parentPath = path.dirname(targetPath);
      const parentRealPath = await realpath(parentPath);
      if (!isPathWithinRoot(rootRealPath, parentRealPath)) {
        sendError(ws, "ROOT", message.i);
        return;
      }
      cloneDestination = safePath;
    }

    const args = ["clone"];
    if (message.b) {
      args.push("--branch", message.b);
    }
    args.push(repoUrl);
    if (cloneDestination) {
      args.push(cloneDestination);
    }

    const result = await execGitCommand(cloneCwd, args, message.i);
    
    const response: GitCloneResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gl",
      i: message.i,
      o: 1,
      ...(result.summary ? { m: result.summary } : {}),
    };
    sendJson(ws, response);
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_clone_failed");
    const response: GitCloneResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gl",
      i: message.i,
      o: 0,
      m: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function handleGitAdd(message: GitAddRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    const args = ["add"];
    if (message.A) {
      args.push("-A");
    } else if (message.f) {
      args.push(message.f);
    } else {
      args.push(".");
    }
    
    const result = await execGitCommand(targetPath, args, message.i);
    
    const response: GitAddResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gb",
      i: message.i,
      o: 1,
      ...(result.summary ? { m: result.summary } : {}),
    };
    sendJson(ws, response);
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_add_failed");
    const response: GitAddResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gb",
      i: message.i,
      o: 0,
      m: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function handleGitCommit(message: GitCommitRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    const args = ["commit", "-m", message.m];
    if (message.a) {
      args.push("-a");
    }
    
    const result = await execGitCommand(targetPath, args, message.i);
    const hashMatch = result.stdout.match(/\[.+\s([a-f0-9]+)\]/);
    const hash = hashMatch ? hashMatch[1] : undefined;
    
    const response: GitCommitResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "go",
      i: message.i,
      o: 1,
      ...(hash ? { h: hash } : {}),
      ...(result.summary ? { m: result.summary } : {}),
    };
    sendJson(ws, response);
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_commit_failed");
    const response: GitCommitResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "go",
      i: message.i,
      o: 0,
      m: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function handleGitPush(message: GitPushRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    const args = ["push"];
    if (message.o) {
      args.push(message.o);
    }
    if (message.b) {
      args.push(message.b);
    }
    
    const result = await execGitCommand(targetPath, args, message.i);
    
    const response: GitPushResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gd",
      i: message.i,
      o: 1,
      ...(result.summary ? { m: result.summary } : {}),
    };
    sendJson(ws, response);
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_push_failed");
    const response: GitPushResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gd",
      i: message.i,
      o: 0,
      m: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function handleGitPull(message: GitPullRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    const args = ["pull"];
    if (message.o) {
      args.push(message.o);
    }
    if (message.b) {
      args.push(message.b);
    }
    
    const result = await execGitCommand(targetPath, args, message.i);
    
    const response: GitPullResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gn",
      i: message.i,
      o: 1,
      ...(result.summary ? { m: result.summary } : {}),
    };
    sendJson(ws, response);
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_pull_failed");
    const response: GitPullResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gn",
      i: message.i,
      o: 0,
      m: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function handleGitBranch(message: GitBranchRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    const action = message.a || "list";
      let result;
    
    if (action === "list") {
      result = await execGitCommand(targetPath, ["branch", "-a"], message.i);
      const branches = result.stdout.split("\n")
        .filter(line => line.trim().length > 0)
        .map(line => line.replace(/^[*\s]+/, "").trim());
      const current = result.stdout.split("\n")
        .find(line => line.startsWith("*"))
        ?.replace(/^\*\s+/, "")
        ?.trim();
      
      const response: GitBranchResponseMessage = {
        v: WS_PROTOCOL_VERSION,
        t: "gu",
        i: message.i,
        o: 1,
        b: branches,
        ...(current ? { c: current } : {}),
      };
      sendJson(ws, response);
    } else if (action === "create" && message.n) {
      const createResult = await execGitCommand(targetPath, ["branch", message.n], message.i);
      const response: GitBranchResponseMessage = {
        v: WS_PROTOCOL_VERSION,
        t: "gu",
        i: message.i,
        o: 1,
        ...(createResult.summary ? { m: createResult.summary } : {}),
      };
      sendJson(ws, response);
    } else if (action === "delete" && message.n) {
      const deleteResult = await execGitCommand(targetPath, ["branch", "-d", message.n], message.i);
      const response: GitBranchResponseMessage = {
        v: WS_PROTOCOL_VERSION,
        t: "gu",
        i: message.i,
        o: 1,
        ...(deleteResult.summary ? { m: deleteResult.summary } : {}),
      };
      sendJson(ws, response);
    } else {
      throw new Error("Invalid branch action or missing branch name");
    }
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_branch_failed");
    const response: GitBranchResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gu",
      i: message.i,
      o: 0,
      m: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function handleGitCheckout(message: GitCheckoutRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    const args = ["checkout"];
    if (message.c) {
      args.push("-b");
    }
    args.push(message.b);
    
    const result = await execGitCommand(targetPath, args, message.i);
    
    const response: GitCheckoutResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gy",
      i: message.i,
      o: 1,
      ...(result.summary ? { m: result.summary } : {}),
    };
    sendJson(ws, response);
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_checkout_failed");
    const response: GitCheckoutResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gy",
      i: message.i,
      o: 0,
      m: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function handleGitConfig(message: GitConfigRequestMessage): Promise<void> {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const safePath = sanitizeRelativePath(message.p);
  if (!safePath) {
    sendError(ws, "PATH", message.i);
    return;
  }

  const rootPath = resolveRootAlias(message.r);
  if (!rootPath) {
    sendError(ws, "ROOT", message.i);
    return;
  }

  const targetPath = path.resolve(rootPath, safePath);

  try {
    const rootRealPath = await realpath(rootPath);
    const targetRealPath = await realpath(targetPath);
    if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
      sendError(ws, "ROOT", message.i);
      return;
    }

    const stat = await lstat(targetRealPath);
    if (!stat.isDirectory()) {
      sendError(ws, "PATH", message.i);
      return;
    }

    if (message.a === "get") {
      const current = await readGitConfigSnapshot(targetRealPath, message.i);
      const response: GitConfigResponseMessage = {
        v: WS_PROTOCOL_VERSION,
        t: "gv",
        i: message.i,
        o: 1,
        ...(current.name ? { n: current.name } : {}),
        ...(current.email ? { e: current.email } : {}),
        ...(current.helper ? { h: current.helper } : {}),
        a: current.authReady,
      };
      sendJson(ws, response);
      return;
    }

    const scopeArgs = message.g === 1 ? ["--global"] : ["--local"];
    const name = typeof message.n === "string" ? message.n.trim() : "";
    const email = typeof message.e === "string" ? message.e.trim() : "";
    if (!name && !email && message.cm !== 1) {
      const response: GitConfigResponseMessage = {
        v: WS_PROTOCOL_VERSION,
        t: "gv",
        i: message.i,
        o: 0,
        m: "no_git_config_values_provided",
      };
      sendJson(ws, response);
      return;
    }
    if (email && !looksLikeEmail(email)) {
      const response: GitConfigResponseMessage = {
        v: WS_PROTOCOL_VERSION,
        t: "gv",
        i: message.i,
        o: 0,
        m: "invalid_email_format",
      };
      sendJson(ws, response);
      return;
    }

    if (name) {
      await execGitCommand(targetRealPath, ["config", ...scopeArgs, "user.name", name], message.i);
    }
    if (email) {
      await execGitCommand(targetRealPath, ["config", ...scopeArgs, "user.email", email], message.i);
    }
    if (message.cm === 1) {
      await execGitCommand(targetRealPath, ["config", "--global", "credential.helper", "manager-core"], message.i);
    }

    const updated = await readGitConfigSnapshot(targetRealPath, message.i);
    const response: GitConfigResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gv",
      i: message.i,
      o: 1,
      ...(updated.name ? { n: updated.name } : {}),
      ...(updated.email ? { e: updated.email } : {}),
      ...(updated.helper ? { h: updated.helper } : {}),
      a: updated.authReady,
      m: "git config saved",
    };
    sendJson(ws, response);
  } catch (error) {
    const errorMsg = extractGitFailureMessage(error, "git_config_failed");
    const response: GitConfigResponseMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "gv",
      i: message.i,
      o: 0,
      m: errorMsg,
    };
    sendJson(ws, response);
  }
}

async function readGitConfigSnapshot(
  cwd: string,
  requestId?: number,
): Promise<{ name?: string; email?: string; helper?: string; authReady: 0 | 1 }> {
  const nameLocal = await readGitConfigValue(cwd, ["config", "--local", "--get", "user.name"], requestId);
  const nameGlobal = await readGitConfigValue(cwd, ["config", "--global", "--get", "user.name"], requestId);
  const emailLocal = await readGitConfigValue(cwd, ["config", "--local", "--get", "user.email"], requestId);
  const emailGlobal = await readGitConfigValue(cwd, ["config", "--global", "--get", "user.email"], requestId);
  const helperGlobal = await readGitConfigValue(cwd, ["config", "--global", "--get", "credential.helper"], requestId);

  const name = nameLocal ?? nameGlobal;
  const email = emailLocal ?? emailGlobal;
  const helper = helperGlobal;
  return {
    ...(name ? { name } : {}),
    ...(email ? { email } : {}),
    ...(helper ? { helper } : {}),
    authReady: helper ? 1 : 0,
  };
}

async function readGitConfigValue(cwd: string, args: string[], requestId?: number): Promise<string | undefined> {
  try {
    const result = await execGitCommand(cwd, args, requestId);
    const value = result.stdout.trim();
    return value ? value : undefined;
  } catch {
    return undefined;
  }
}

function looksLikeEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

type GitCommandResult = {
  stdout: string;
  stderr: string;
  summary?: string;
};

// Git Helper Function
async function execGitCommand(cwd: string, args: string[], requestId?: number): Promise<GitCommandResult> {
  const renderedArgs = renderGitArgsForLog(args);
  log(`git start cwd=${cwd} args=${renderedArgs}`);
  appendContinuityLog("git", `$ git ${renderedArgs}`);
  emitGitLog(requestId, "meta", `$ git ${renderedArgs}`);

  return new Promise((resolve, reject) => {
    const child = spawn("git", args, {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: "0",
      },
    });
    
    let stdout = "";
    let stderr = "";
    let didTimeout = false;
    let stdoutTail = "";
    let stderrTail = "";
    let emittedLines = 0;
    let outputTruncated = false;

    const emitCommandLine = (stream: "out" | "err", line: string): void => {
      const normalized = normalizeGitLogLine(line);
      if (!normalized) {
        return;
      }
      if (emittedLines >= GIT_LOG_MAX_LINES) {
        if (!outputTruncated) {
          outputTruncated = true;
          emitGitLog(requestId, "meta", `additional git output truncated after ${GIT_LOG_MAX_LINES} lines`);
        }
        return;
      }
      emittedLines += 1;
      emitGitLog(requestId, stream, normalized);
    };

    const processChunk = (stream: "out" | "err", chunk: string): void => {
      const next = (stream === "out" ? stdoutTail : stderrTail) + chunk.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      const parts = next.split("\n");
      const tail = parts.pop() ?? "";
      for (const line of parts) {
        emitCommandLine(stream, line);
      }
      if (stream === "out") {
        stdoutTail = tail;
      } else {
        stderrTail = tail;
      }
    };

    const flushTail = (): void => {
      if (stdoutTail) {
        emitCommandLine("out", stdoutTail);
        stdoutTail = "";
      }
      if (stderrTail) {
        emitCommandLine("err", stderrTail);
        stderrTail = "";
      }
    };

    const timeout = setTimeout(() => {
      didTimeout = true;
      child.kill();
    }, GIT_COMMAND_TIMEOUT_MS);
    timeout.unref();
    
    child.stdout?.on("data", (data) => {
      const chunk = data.toString();
      stdout += chunk;
      processChunk("out", chunk);
    });
    
    child.stderr?.on("data", (data) => {
      const chunk = data.toString();
      stderr += chunk;
      processChunk("err", chunk);
    });
    
    child.on("close", (code) => {
      clearTimeout(timeout);
      flushTail();
      const summary = summarizeGitOutput(stdout, stderr);
      if (code !== 0) {
        const message = summary ?? (didTimeout
          ? `Git command timed out after ${GIT_COMMAND_TIMEOUT_MS}ms`
          : `Git command failed with exit code ${code}`);
        log(`git failed cwd=${cwd} args=${renderedArgs} code=${code ?? "null"} output=${singleLine(message)}`);
        emitGitLog(requestId, didTimeout ? "meta" : "err", message);
        const error = new Error(message) as Error & {
          stdout?: string;
          stderr?: string;
          summary?: string;
        };
        error.stdout = stdout;
        error.stderr = stderr;
        if (summary) {
          error.summary = summary;
        }
        reject(error);
      } else {
        if (summary) {
          log(`git done cwd=${cwd} args=${renderedArgs} output=${singleLine(summary)}`);
          appendContinuityLog("git", `done ${renderedArgs} output=${singleLine(summary)}`);
        } else {
          log(`git done cwd=${cwd} args=${renderedArgs}`);
          appendContinuityLog("git", `done ${renderedArgs}`);
        }
        emitGitLog(requestId, "meta", "git command completed");
        resolve(summary ? { stdout, stderr, summary } : { stdout, stderr });
      }
    });
    
    child.on("error", (err) => {
      clearTimeout(timeout);
      log(`git spawn error cwd=${cwd} args=${renderedArgs} error=${err.message}`);
      appendContinuityLog("git", `spawn_error ${renderedArgs} error=${singleLine(err.message)}`);
      emitGitLog(requestId, "err", err.message);
      reject(err);
    });
  });
}

function emitGitLog(requestId: number | undefined, stream: GitLogMessage["s"], message: string): void {
  const ws = socket;
  if (!ws || ws.readyState !== WebSocket.OPEN || !handshakeComplete || requestId === undefined) {
    return;
  }
  const text = normalizeGitLogLine(message);
  if (!text) {
    return;
  }
  appendContinuityLog("git", `[${stream}] ${text}`);
  const payload: GitLogMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gq",
    i: requestId,
    s: stream,
    m: text,
  };
  sendJson(ws, payload);
}

function normalizeGitLogLine(value: string): string {
  const noAnsi = value.replace(/\u001b\[[0-9;]*m/g, "");
  const redacted = redactSensitiveText(noAnsi).replace(/(https?:\/\/)([^/\s:@]+):([^@\s]+)@/gi, "$1***:***@");
  const collapsed = redacted.replace(/\s+/g, " ").trim();
  if (!collapsed) {
    return "";
  }
  return truncateText(collapsed, 500);
}

function summarizeGitOutput(stdout: string, stderr: string): string | undefined {
  const joined = [stderr.trim(), stdout.trim()].filter(Boolean).join("\n").trim();
  if (!joined) {
    return undefined;
  }
  return truncateText(joined, 1200);
}

function truncateText(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, Math.max(0, maxLength - 3))}...`;
}

function chunkTextForStream(text: string, maxBytes: number): string[] {
  if (!text) {
    return [""];
  }

  const chunks: string[] = [];
  let current = "";
  let currentBytes = 0;

  for (const char of text) {
    const charBytes = Buffer.byteLength(char, "utf8");
    if (current && currentBytes + charBytes > maxBytes) {
      chunks.push(current);
      current = char;
      currentBytes = charBytes;
      continue;
    }
    current += char;
    currentBytes += charBytes;
  }

  if (current) {
    chunks.push(current);
  }

  return chunks.length > 0 ? chunks : [""];
}

function isAllowedProxyRequestHeader(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower === "host" || lower === "connection" || lower === "upgrade" || lower === "content-length" || lower === "cookie") {
    return false;
  }
  if (lower.startsWith("sec-websocket")) {
    return false;
  }
  return true;
}

function toProxyHeaderEntries(headers: Headers): ProxyHeaderEntry[] {
  const list: ProxyHeaderEntry[] = [];
  for (const [name, value] of headers.entries()) {
    const lower = name.toLowerCase();
    if (lower === "connection" || lower === "transfer-encoding") {
      continue;
    }
    list.push([name, value]);
  }
  return list;
}

function renderGitArgsForLog(args: string[]): string {
  return args.map((arg) => {
    const redacted = redactGitArg(arg);
    return /\s/.test(redacted) ? JSON.stringify(redacted) : redacted;
  }).join(" ");
}

function redactGitArg(arg: string): string {
  if (!/^https?:\/\//i.test(arg)) {
    return arg;
  }
  try {
    const parsed = new URL(arg);
    if (parsed.username || parsed.password) {
      parsed.username = parsed.username ? "***" : "";
      parsed.password = parsed.password ? "***" : "";
    }
    return parsed.toString();
  } catch {
    return arg;
  }
}

function singleLine(value: string): string {
  return redactSensitiveText(value).replace(/\s+/g, " ").trim();
}

function extractGitFailureMessage(error: unknown, fallback: string): string {
  if (error && typeof error === "object" && "summary" in error) {
    const summary = (error as { summary?: unknown }).summary;
    if (typeof summary === "string" && summary.trim().length > 0) {
      return summary;
    }
  }
  if (error instanceof Error && error.message.trim().length > 0) {
    return truncateText(error.message.trim(), 1200);
  }
  return fallback;
}

function parseDirectoryRequest(value: unknown): DirectoryRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p", "l", "k"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "dr") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  if (!isInteger(value.l) || value.l < 1 || value.l > MAX_DIRECTORY_LIMIT) {
    return null;
  }
  if (value.k !== undefined && (typeof value.k !== "string" || value.k.length > 128)) {
    return null;
  }
  return value as unknown as DirectoryRequestMessage;
}

function parseStartSession(value: unknown): StartSessionMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "s", "p", "j"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "si") {
    return null;
  }
  if (!isUint32(value.i) || !matches(value.s, /^[A-Za-z0-9_-]{1,64}$/)) {
    return null;
  }
  if (value.p !== undefined && (typeof value.p !== "string" || value.p.length > 512)) {
    return null;
  }
  if (value.j !== undefined && !isValidSessionJitCredential(value.j)) {
    return null;
  }
  return value as unknown as StartSessionMessage;
}

function isValidSessionJitCredential(value: unknown): value is SessionJitCredential {
  if (!isObject(value)) {
    return false;
  }
  if (!hasOnlyKeys(value, ["t", "e", "s", "n", "r", "v"])) {
    return false;
  }
  if (typeof value.t !== "string" || value.t.length < 16 || value.t.length > 2048) {
    return false;
  }
  if (!isInteger(value.e)) {
    return false;
  }
  const now = Date.now();
  if (value.e < now - 10000 || value.e > now + SESSION_JIT_MAX_TTL_MS) {
    return false;
  }
  if (value.s !== undefined && (typeof value.s !== "string" || value.s.length < 1 || value.s.length > 128)) {
    return false;
  }
  if (value.n !== undefined && (typeof value.n !== "string" || !isJitAllowedEnvVarName(value.n))) {
    return false;
  }
  if (value.r !== undefined && !matches(value.r, /^[A-Za-z0-9._:-]{1,128}$/)) {
    return false;
  }
  if (value.v !== undefined && !isValidJitEnvPairs(value.v)) {
    return false;
  }
  return true;
}

function parseJitKillSwitchRequest(value: unknown): JitKillSwitchRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "s", "r", "x", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "jk") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.s !== undefined && !matches(value.s, /^[A-Za-z0-9_-]{1,64}$/)) {
    return null;
  }
  if (value.r !== undefined && !matches(value.r, /^[A-Za-z0-9._:-]{1,128}$/)) {
    return null;
  }
  if (value.x !== undefined && value.x !== 0 && value.x !== 1) {
    return null;
  }
  if (value.m !== undefined && (typeof value.m !== "string" || value.m.length > 128)) {
    return null;
  }
  return value as unknown as JitKillSwitchRequestMessage;
}

function parseSessionStatusRequest(value: unknown): SessionStatusRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "p"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "sq") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  return value as unknown as SessionStatusRequestMessage;
}

function parseSessionLogRequest(value: unknown): SessionLogRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "x", "l"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "sl") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.x, /^[A-Za-z0-9_-]{8,24}$/)) {
    return null;
  }
  if (!isInteger(value.l) || value.l < 1 || value.l > SESSION_LOG_REPLAY_MAX_LINES) {
    return null;
  }
  return value as unknown as SessionLogRequestMessage;
}

function parsePortProxyRequest(value: unknown): PortProxyRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "p", "m", "u", "h", "b"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "pr") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!isInteger(value.p) || value.p < 1 || value.p > 65535) {
    return null;
  }
  if (!matches(value.m, /^[A-Z]{3,10}$/)) {
    return null;
  }
  if (typeof value.u !== "string" || value.u.length < 1 || value.u.length > 2048) {
    return null;
  }
  if (!Array.isArray(value.h) || value.h.length > 64 || !value.h.every(isProxyHeaderEntry)) {
    return null;
  }
  if (value.b !== undefined && (typeof value.b !== "string" || value.b.length > 2_000_000)) {
    return null;
  }
  return value as unknown as PortProxyRequestMessage;
}

function isProxyHeaderEntry(value: unknown): value is ProxyHeaderEntry {
  if (!Array.isArray(value) || value.length !== 2) {
    return false;
  }
  const [name, headerValue] = value;
  if (typeof name !== "string" || typeof headerValue !== "string") {
    return false;
  }
  if (!/^[A-Za-z0-9-]{1,64}$/.test(name)) {
    return false;
  }
  return headerValue.length <= 4096;
}

function parseSetupStatusRequest(value: unknown): SetupStatusRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "cf") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  return value as unknown as SetupStatusRequestMessage;
}

function parseSetupSaveRequest(value: unknown): SetupSaveRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "u", "a", "oc", "oh", "os", "op", "om", "rt"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "cu") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (typeof value.u !== "string" || value.u.length > 512) {
    return null;
  }
  if (typeof value.a !== "string" || value.a.length > 512) {
    return null;
  }
  if (value.oc !== undefined && (typeof value.oc !== "string" || value.oc.length > 256)) {
    return null;
  }
  if (value.oh !== undefined && (typeof value.oh !== "string" || value.oh.length > 128)) {
    return null;
  }
  if (value.os !== undefined && (!isInteger(value.os) || value.os < 1 || value.os > 65535)) {
    return null;
  }
  if (value.op !== undefined && (typeof value.op !== "string" || value.op.length > 128)) {
    return null;
  }
  if (value.om !== undefined && (typeof value.om !== "string" || value.om.length > 128)) {
    return null;
  }
  if (value.rt !== undefined && (!isInteger(value.rt) || value.rt < 1000 || value.rt > 120000)) {
    return null;
  }
  return value as unknown as SetupSaveRequestMessage;
}

function parseConfigCheckRequest(value: unknown): ConfigCheckPushRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "k", "ph", "sc", "tid", "tv", "ts", "ap", "pd", "alg", "sg", "pm", "cfg"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "cc" || value.k !== "cfg") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.ph !== undefined && value.ph !== "session-init" && value.ph !== "runtime") {
    return null;
  }
  if (value.sc !== undefined && value.sc !== "session-init" && value.sc !== "full") {
    return null;
  }
  if (!matches(value.tid, /^[a-z0-9][a-z0-9_-]{2,63}$/)) {
    return null;
  }
  if (!matches(value.tv, /^[A-Za-z0-9._-]{1,32}$/)) {
    return null;
  }
  if (!isInteger(value.ts) || value.ts < 0) {
    return null;
  }
  if (typeof value.ap !== "string" || value.ap.length > 256) {
    return null;
  }
  if (!matches(value.pd, /^[A-Za-z0-9_-]{43}$/)) {
    return null;
  }
  if (value.alg !== undefined && (typeof value.alg !== "string" || value.alg.length < 1 || value.alg.length > 64)) {
    return null;
  }
  if (value.sg !== undefined && (typeof value.sg !== "string" || value.sg.length < 1 || value.sg.length > 512)) {
    return null;
  }
  if (value.pm !== undefined && value.pm !== "off" && value.pm !== "read-only" && value.pm !== "restricted") {
    return null;
  }
  if (!isObject(value.cfg)) {
    return null;
  }
  return value as unknown as ConfigCheckPushRequestMessage;
}

function readDeclaredPolicyMode(config: Record<string, unknown>): "off" | "read-only" | "restricted" | undefined {
  if (!isObject(config.codenucleus)) {
    return undefined;
  }
  const codenucleus = config.codenucleus;
  if (!isObject(codenucleus.policy)) {
    return undefined;
  }
  const mode = codenucleus.policy.mode;
  if (mode === "off" || mode === "read-only" || mode === "restricted") {
    return mode;
  }
  return undefined;
}

function parseTerminateSession(value: unknown): TerminateSessionMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "s"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "st") {
    return null;
  }
  if (!isUint32(value.i) || !matches(value.s, /^[A-Za-z0-9_-]{1,64}$/)) {
    return null;
  }
  return value as unknown as TerminateSessionMessage;
}

function parseMkdirRequest(value: unknown): MkdirRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "md") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  return value as unknown as MkdirRequestMessage;
}

function parseRmdirRequest(value: unknown): RmdirRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "rd") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  return value as unknown as RmdirRequestMessage;
}

function parseRenameRequest(value: unknown): RenameRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "s", "d"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "rn") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.s !== "string" || value.s.length > 512) {
    return null;
  }
  if (typeof value.d !== "string" || value.d.length > 512) {
    return null;
  }
  return value as unknown as RenameRequestMessage;
}

// Git Request Parsers
function parseGitStatusRequest(value: unknown): GitStatusRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gs") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  return value as unknown as GitStatusRequestMessage;
}

function parseGitInitRequest(value: unknown): GitInitRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gi") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  return value as unknown as GitInitRequestMessage;
}

function parseGitCloneRequest(value: unknown): GitCloneRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p", "u", "b"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gk") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  if (typeof value.u !== "string" || value.u.length > 2048) {
    return null;
  }
  if (value.b !== undefined && (typeof value.b !== "string" || value.b.length > 256)) {
    return null;
  }
  return value as unknown as GitCloneRequestMessage;
}

function parseGitAddRequest(value: unknown): GitAddRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p", "f", "A"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "ga") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  if (value.f !== undefined && (typeof value.f !== "string" || value.f.length > 512)) {
    return null;
  }
  if (value.A !== undefined && value.A !== 0 && value.A !== 1) {
    return null;
  }
  return value as unknown as GitAddRequestMessage;
}

function parseGitCommitRequest(value: unknown): GitCommitRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p", "m", "a"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gp") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  if (typeof value.m !== "string" || value.m.length > 1024) {
    return null;
  }
  if (value.a !== undefined && value.a !== 0 && value.a !== 1) {
    return null;
  }
  return value as unknown as GitCommitRequestMessage;
}

function parseGitPushRequest(value: unknown): GitPushRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p", "o", "b"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gh") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  if (value.o !== undefined && (typeof value.o !== "string" || value.o.length > 64)) {
    return null;
  }
  if (value.b !== undefined && (typeof value.b !== "string" || value.b.length > 256)) {
    return null;
  }
  return value as unknown as GitPushRequestMessage;
}

function parseGitPullRequest(value: unknown): GitPullRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p", "o", "b"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gm") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  if (value.o !== undefined && (typeof value.o !== "string" || value.o.length > 64)) {
    return null;
  }
  if (value.b !== undefined && (typeof value.b !== "string" || value.b.length > 256)) {
    return null;
  }
  return value as unknown as GitPullRequestMessage;
}

function parseGitBranchRequest(value: unknown): GitBranchRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p", "a", "n"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gc") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  if (value.a !== undefined && !["list", "create", "delete"].includes(value.a as string)) {
    return null;
  }
  if (value.n !== undefined && (typeof value.n !== "string" || value.n.length > 256)) {
    return null;
  }
  return value as unknown as GitBranchRequestMessage;
}

function parseGitCheckoutRequest(value: unknown): GitCheckoutRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p", "b", "c"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gx") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  if (typeof value.b !== "string" || value.b.length > 256) {
    return null;
  }
  if (value.c !== undefined && value.c !== 0 && value.c !== 1) {
    return null;
  }
  return value as unknown as GitCheckoutRequestMessage;
}

function parseGitConfigRequest(value: unknown): GitConfigRequestMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "r", "p", "a", "n", "e", "g", "cm"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gf") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.r, /^[A-Za-z0-9_-]{1,16}$/)) {
    return null;
  }
  if (typeof value.p !== "string" || value.p.length > 512) {
    return null;
  }
  if (value.a !== "get" && value.a !== "set") {
    return null;
  }
  if (value.n !== undefined && (typeof value.n !== "string" || value.n.length > 256)) {
    return null;
  }
  if (value.e !== undefined && (typeof value.e !== "string" || value.e.length > 256)) {
    return null;
  }
  if (value.g !== undefined && value.g !== 0 && value.g !== 1) {
    return null;
  }
  if (value.cm !== undefined && value.cm !== 0 && value.cm !== 1) {
    return null;
  }
  return value as unknown as GitConfigRequestMessage;
}

function parseErrorMessage(value: unknown): ErrorMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "c", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "e") {
    return null;
  }
  if (!isErrorCode(value.c)) {
    return null;
  }
  if (value.i !== undefined && !isUint32(value.i)) {
    return null;
  }
  if (value.m !== undefined && (typeof value.m !== "string" || value.m.length === 0 || value.m.length > 256)) {
    return null;
  }
  return value as unknown as ErrorMessage;
}

function sendError(ws: WebSocket, code: ErrorCode, requestId?: number): void {
  sendJson(ws, { v: WS_PROTOCOL_VERSION, t: "e", i: requestId, c: code });
}

function sendJson(ws: WebSocket, payload: object): void {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function telemetryFingerprint(hostname: string, platform: string, version: string): number {
  const input = `${hostname}|${platform}|${version}`;
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function defaultDeviceId(): string {
  const base = `${os.hostname()}|${os.platform()}|${AGENT_VERSION}`;
  const digest = createHash("sha256").update(base).digest("base64url");
  return `dev_${digest.slice(0, 16)}`;
}

function sign(secret: string, value: string): string {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

function deriveAuthKeyId(secret: string): string {
  return createHash("sha256").update(secret).digest("base64url").slice(0, 24);
}

function canonicalH1ForKeyId(deviceId: string, nonce: string, timestamp: number, authKeyId: string): string {
  return `h1|1|${deviceId}|${nonce}|${timestamp}|ak:${authKeyId}`;
}

function isJitCredentialUsable(credential: SessionJitCredential): boolean {
  if (!credential || typeof credential.t !== "string" || credential.t.length < 16) {
    return false;
  }
  if (!isInteger(credential.e)) {
    return false;
  }
  const now = Date.now();
  if (credential.e <= now + SESSION_JIT_MIN_TTL_MS) {
    return false;
  }
  if (credential.e > now + SESSION_JIT_MAX_TTL_MS) {
    return false;
  }
  if (credential.s !== undefined && (typeof credential.s !== "string" || credential.s.length > 128)) {
    return false;
  }
  if (credential.n !== undefined && !isJitAllowedEnvVarName(credential.n)) {
    return false;
  }
  if (credential.r !== undefined && !matches(credential.r, /^[A-Za-z0-9._:-]{1,128}$/)) {
    return false;
  }
  if (credential.v !== undefined && !isValidJitEnvPairs(credential.v)) {
    return false;
  }
  return true;
}

function fingerprintJitCredential(credential: SessionJitCredential): string {
  const pairs = Array.isArray(credential.v)
    ? credential.v.map(([name, value]) => `${name}=${value}`).join("|")
    : "";
  const canonical = `${credential.r ?? ""}|${credential.n ?? SESSION_JIT_DEFAULT_ENV_VAR}|${credential.e}|${credential.s ?? ""}|${pairs}|${credential.t}`;
  return createHash("sha256").update(canonical).digest("base64url").slice(0, 24);
}

function buildOpencodeSpawnEnv(jitCredential?: SessionJitCredential): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  if (!jitCredential || !isJitCredentialUsable(jitCredential)) {
    return env;
  }

  const envVarName = jitCredential.n ?? SESSION_JIT_DEFAULT_ENV_VAR;
  env[envVarName] = jitCredential.t;
  env.OPENCODE_JIT_TOKEN_EXPIRES_AT = String(jitCredential.e);
  if (jitCredential.s) {
    env.OPENCODE_JIT_SCOPE = jitCredential.s;
  }
  if (jitCredential.v) {
    for (const [name, value] of jitCredential.v) {
      if (name === envVarName) {
        continue;
      }
      env[name] = value;
      runtimeSensitiveValues.add(value);
    }
  }
  runtimeSensitiveValues.add(jitCredential.t);
  return env;
}

type SessionSnapshotMetadata = {
  model: {
    providerId: string;
    modelId: string;
    agentVersion: string;
  };
  env: Record<string, string>;
  mcp: {
    env: Record<string, string>;
    configPath?: string;
    activeToolConfig?: string;
  };
  runtime: {
    nodeVersion: string;
    platform: string;
    jitCredentialExpiresAt?: number;
  };
};

function captureSessionMetadata(folderPath: string, jitCredentialExpiry?: number): SessionSnapshotMetadata {
  const envSnapshot = snapshotEnvironmentVariables();
  const mcpEnv: Record<string, string> = {};
  for (const [key, value] of Object.entries(envSnapshot)) {
    if (key.startsWith("MCP_") || key.startsWith("OPENCODE_MCP_")) {
      mcpEnv[key] = value;
    }
  }

  return {
    model: {
      providerId: OPENCODE_PROVIDER_ID,
      modelId: OPENCODE_MODEL_ID,
      agentVersion: AGENT_VERSION,
    },
    env: {
      ...envSnapshot,
      AGENT_PROJECT_ROOT: folderPath,
    },
    mcp: {
      env: mcpEnv,
      ...(process.env.OPENCODE_CONFIG_PATH ? { configPath: process.env.OPENCODE_CONFIG_PATH } : {}),
      ...(process.env.OPENCODE_MCP_TOOLS ? { activeToolConfig: process.env.OPENCODE_MCP_TOOLS } : {}),
    },
    runtime: {
      nodeVersion: process.version,
      platform: `${process.platform}/${process.arch}`,
      ...(jitCredentialExpiry ? { jitCredentialExpiresAt: jitCredentialExpiry } : {}),
    },
  };
}

function snapshotEnvironmentVariables(): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(process.env)) {
    if (typeof rawValue !== "string" || rawValue.length === 0) {
      continue;
    }
    if (!/^(OPENCODE_|MCP_|NODE_ENV$|SHELL$|PATH$|HOME$|USERPROFILE$|PWD$)/.test(key)) {
      continue;
    }
    selected[key] = redactSensitiveText(rawValue);
  }
  return selected;
}

function secureEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return timingSafeEqual(leftBuffer, rightBuffer);
}

function randomToken(length: number): string {
  return randomBytes(length).toString("base64url").slice(0, length);
}

function resolveRootRealPath(rootPath: string): string {
  try {
    return realpathSync(rootPath);
  } catch {
    return rootPath;
  }
}

function clampInt(value: number, min: number, max: number): number {
  if (!Number.isInteger(value)) {
    return min;
  }
  if (value < min) {
    return min;
  }
  if (value > max) {
    return max;
  }
  return value;
}

function clampUint32(value: number): number {
  if (!Number.isFinite(value) || value < 0) {
    return 0;
  }
  if (value > 0xffffffff) {
    return 0xffffffff;
  }
  return Math.floor(value);
}

function clearTimer(timer: NodeJS.Timeout | null): void {
  if (timer) {
    clearTimeout(timer);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const known = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!known.has(key)) {
      return false;
    }
  }
  return true;
}

function matches(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

function isUint32(value: unknown): value is number {
  return isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function isErrorCode(value: unknown): value is ErrorCode {
  return (
    value === "AUTH" ||
    value === "PROTO" ||
    value === "PATH" ||
    value === "ROOT" ||
    value === "LIMIT" ||
    value === "FLOW" ||
    value === "INTERNAL" ||
    value === "UPDATE_REQUIRED"
  );
}

async function ensureRuntimeConfig(): Promise<{ controlPlaneUrl: string; agentAuthToken: string }> {
  const envPath = path.join(ALLOWED_PROJECT_ROOT_REAL, ".env");
  const configureRequested = process.argv.includes("--configure-env") || process.argv.includes("--setup");
  const existingEnvFile = await readDotenvFile(envPath);
  const hasEnvFile = existingEnvFile !== null;

  const alreadyConfigured = Boolean((process.env.CONTROL_PLANE_URL ?? "").trim()) && Boolean((process.env.AGENT_AUTH_TOKEN ?? "").trim());
  if (!configureRequested && hasEnvFile && alreadyConfigured) {
    return loadRuntimeConfig();
  }

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    if (!alreadyConfigured) {
      throw new Error("missing required env. run with an interactive terminal to set up .env");
    }
    return loadRuntimeConfig();
  }

  const seededValues = {
    CONTROL_PLANE_URL: (process.env.CONTROL_PLANE_URL ?? existingEnvFile?.CONTROL_PLANE_URL ?? "ws://127.0.0.1:8787").trim(),
    AGENT_AUTH_TOKEN: (process.env.AGENT_AUTH_TOKEN ?? existingEnvFile?.AGENT_AUTH_TOKEN ?? "").trim(),
    OPENCODE_COMMAND: (process.env.OPENCODE_COMMAND ?? existingEnvFile?.OPENCODE_COMMAND ?? OPENCODE_COMMAND).trim(),
    OPENCODE_HOST: (process.env.OPENCODE_HOST ?? existingEnvFile?.OPENCODE_HOST ?? OPENCODE_HOST).trim(),
    OPENCODE_START_PORT: (process.env.OPENCODE_START_PORT ?? existingEnvFile?.OPENCODE_START_PORT ?? String(OPENCODE_START_PORT)).trim(),
    OPENCODE_PROVIDER_ID: (process.env.OPENCODE_PROVIDER_ID ?? existingEnvFile?.OPENCODE_PROVIDER_ID ?? OPENCODE_PROVIDER_ID).trim(),
    OPENCODE_MODEL_ID: (process.env.OPENCODE_MODEL_ID ?? existingEnvFile?.OPENCODE_MODEL_ID ?? OPENCODE_MODEL_ID).trim(),
    REQUEST_TIMEOUT_MS: (process.env.REQUEST_TIMEOUT_MS ?? existingEnvFile?.REQUEST_TIMEOUT_MS ?? String(REQUEST_TIMEOUT_MS)).trim(),
  };

  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  try {
    process.stdout.write("\n[agent-daemon] setup dialog\n");
    process.stdout.write(`Project root: ${ALLOWED_PROJECT_ROOT_REAL}\n`);
    process.stdout.write(`Config file: ${envPath}\n\n`);

    const controlPlaneUrl = await promptValue(rl, "CONTROL_PLANE_URL", seededValues.CONTROL_PLANE_URL, true);
    const agentAuthToken = await promptSecretValue(rl, "AGENT_AUTH_TOKEN", seededValues.AGENT_AUTH_TOKEN, true);

    const configureAdvanced = await promptYesNo(rl, "Configure advanced OpenCode options", false);
    let opencodeCommand = seededValues.OPENCODE_COMMAND;
    let opencodeHost = seededValues.OPENCODE_HOST;
    let opencodeStartPort = seededValues.OPENCODE_START_PORT;
    let opencodeProviderId = seededValues.OPENCODE_PROVIDER_ID;
    let opencodeModelId = seededValues.OPENCODE_MODEL_ID;
    let requestTimeoutMs = seededValues.REQUEST_TIMEOUT_MS;

    if (configureAdvanced) {
      opencodeCommand = await promptValue(rl, "OPENCODE_COMMAND", opencodeCommand, true);
      opencodeHost = await promptValue(rl, "OPENCODE_HOST", opencodeHost, true);
      opencodeStartPort = await promptValue(rl, "OPENCODE_START_PORT", opencodeStartPort, true);
      opencodeProviderId = await promptValue(rl, "OPENCODE_PROVIDER_ID", opencodeProviderId, true);
      opencodeModelId = await promptValue(rl, "OPENCODE_MODEL_ID", opencodeModelId, true);
      requestTimeoutMs = await promptValue(rl, "REQUEST_TIMEOUT_MS", requestTimeoutMs, true);
    }

    const merged: Record<string, string> = {
      ...(existingEnvFile ?? {}),
      CONTROL_PLANE_URL: controlPlaneUrl,
      AGENT_AUTH_TOKEN: agentAuthToken,
      OPENCODE_COMMAND: opencodeCommand,
      OPENCODE_HOST: opencodeHost,
      OPENCODE_START_PORT: opencodeStartPort,
      OPENCODE_PROVIDER_ID: opencodeProviderId,
      OPENCODE_MODEL_ID: opencodeModelId,
      REQUEST_TIMEOUT_MS: requestTimeoutMs,
    };

    await writeDotenvFile(envPath, merged);
    await ensureEnvIgnored(ALLOWED_PROJECT_ROOT_REAL);
    loadDotenv({ path: envPath, override: true });
    process.stdout.write("\n[agent-daemon] .env saved. You can re-open this dialog with --configure-env\n\n");
  } finally {
    rl.close();
  }

  return loadRuntimeConfig();
}

function loadRuntimeConfig(): { controlPlaneUrl: string; agentAuthToken: string } {
  const controlPlaneUrl = process.env.CONTROL_PLANE_URL?.trim() ?? "";
  const agentAuthToken = process.env.AGENT_AUTH_TOKEN?.trim() ?? "";
  if (!controlPlaneUrl) {
    throw new Error("missing required env CONTROL_PLANE_URL");
  }
  if (!agentAuthToken) {
    throw new Error("missing required env AGENT_AUTH_TOKEN");
  }
  return { controlPlaneUrl, agentAuthToken };
}

async function readDotenvFile(envPath: string): Promise<Record<string, string> | null> {
  try {
    const raw = await readFile(envPath, "utf8");
    const parsed = parseDotenv(raw);
    const values: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed)) {
      values[key] = String(value);
    }
    return values;
  } catch {
    return null;
  }
}

async function writeDotenvFile(envPath: string, values: Record<string, string>): Promise<void> {
  const orderedKeys = Object.keys(values).sort((left, right) => left.localeCompare(right));
  const lines = [
    "# Auto-generated by agent-daemon setup dialog",
    "# Re-run setup with: npm run dev -- --configure-env",
    "",
  ];
  for (const key of orderedKeys) {
    const value = values[key] ?? "";
    lines.push(`${key}=${serializeEnvValue(value)}`);
  }
  lines.push("");

  await mkdir(path.dirname(envPath), { recursive: true });
  await writeFile(envPath, lines.join("\n"), { encoding: "utf8", mode: 0o600 });
  await chmod(envPath, 0o600).catch(() => {
  });
}

function serializeEnvValue(value: string): string {
  if (/^[A-Za-z0-9_./:-]+$/.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

async function ensureEnvIgnored(rootPath: string): Promise<void> {
  const gitignorePath = path.join(rootPath, ".gitignore");
  try {
    const current = await readFile(gitignorePath, "utf8");
    if (/^\.env$/m.test(current)) {
      return;
    }
    const separator = current.endsWith("\n") ? "" : "\n";
    await writeFile(gitignorePath, `${current}${separator}.env\n`, "utf8");
  } catch {
  }
}

async function promptValue(
  rl: ReturnType<typeof createInterface>,
  label: string,
  defaultValue: string,
  required: boolean,
): Promise<string> {
  while (true) {
    const suffix = defaultValue ? ` [${defaultValue}]` : "";
    const answer = (await rl.question(`${label}${suffix}: `)).trim();
    const value = answer || defaultValue;
    if (!required || value) {
      return value;
    }
    process.stdout.write(`${label} is required.\n`);
  }
}

async function promptSecretValue(
  rl: ReturnType<typeof createInterface>,
  label: string,
  defaultValue: string,
  required: boolean,
): Promise<string> {
  type MaskableReadline = ReturnType<typeof createInterface> & {
    stdoutMuted?: boolean;
    _writeToOutput?: (chunk: string) => void;
  };

  const maskableRl = rl as MaskableReadline;
  const originalWriteToOutput = maskableRl._writeToOutput;

  try {
    while (true) {
      const hasDefault = defaultValue.length > 0;
      const suffix = hasDefault ? " [hidden]" : "";
      process.stdout.write(`${label}${suffix}: `);
      maskableRl.stdoutMuted = true;
      maskableRl._writeToOutput = (chunk: string): void => {
        if (maskableRl.stdoutMuted) {
          if (chunk === "\n" || chunk === "\r\n") {
            process.stdout.write(chunk);
          } else {
            process.stdout.write("*");
          }
          return;
        }
        if (originalWriteToOutput) {
          originalWriteToOutput.call(maskableRl, chunk);
          return;
        }
        process.stdout.write(chunk);
      };

      const answer = (await maskableRl.question(""))
        .trim();

      maskableRl.stdoutMuted = false;
      process.stdout.write("\n");
      const value = answer || defaultValue;
      if (!required || value) {
        return value;
      }
      process.stdout.write(`${label} is required.\n`);
    }
  } finally {
    maskableRl.stdoutMuted = false;
    if (originalWriteToOutput) {
      maskableRl._writeToOutput = originalWriteToOutput;
    }
  }
}

async function promptYesNo(
  rl: ReturnType<typeof createInterface>,
  label: string,
  defaultValue: boolean,
): Promise<boolean> {
  while (true) {
    const suffix = defaultValue ? " [Y/n]" : " [y/N]";
    const answer = (await rl.question(`${label}${suffix}: `)).trim().toLowerCase();
    if (!answer) {
      return defaultValue;
    }
    if (answer === "y" || answer === "yes") {
      return true;
    }
    if (answer === "n" || answer === "no") {
      return false;
    }
  }
}

async function readSetupStatusSnapshot(): Promise<SetupConfigStatus> {
  const existingEnv = await readDotenvFile(ENV_FILE_PATH);
  const source = {
    CONTROL_PLANE_URL: (process.env.CONTROL_PLANE_URL ?? existingEnv?.CONTROL_PLANE_URL ?? "").trim(),
    AGENT_AUTH_TOKEN: (process.env.AGENT_AUTH_TOKEN ?? existingEnv?.AGENT_AUTH_TOKEN ?? "").trim(),
    OPENCODE_COMMAND: (process.env.OPENCODE_COMMAND ?? existingEnv?.OPENCODE_COMMAND ?? OPENCODE_COMMAND).trim(),
    OPENCODE_HOST: (process.env.OPENCODE_HOST ?? existingEnv?.OPENCODE_HOST ?? OPENCODE_HOST).trim(),
    OPENCODE_START_PORT: parseInt(process.env.OPENCODE_START_PORT ?? existingEnv?.OPENCODE_START_PORT ?? String(OPENCODE_START_PORT), 10),
    OPENCODE_PROVIDER_ID: (process.env.OPENCODE_PROVIDER_ID ?? existingEnv?.OPENCODE_PROVIDER_ID ?? OPENCODE_PROVIDER_ID).trim(),
    OPENCODE_MODEL_ID: (process.env.OPENCODE_MODEL_ID ?? existingEnv?.OPENCODE_MODEL_ID ?? OPENCODE_MODEL_ID).trim(),
    REQUEST_TIMEOUT_MS: parseInt(process.env.REQUEST_TIMEOUT_MS ?? existingEnv?.REQUEST_TIMEOUT_MS ?? String(REQUEST_TIMEOUT_MS), 10),
  };

  const hasToken = source.AGENT_AUTH_TOKEN.length > 0;
  return {
    ok: true,
    configured: Boolean(source.CONTROL_PLANE_URL) && hasToken,
    controlPlaneUrl: source.CONTROL_PLANE_URL,
    hasAgentAuthToken: hasToken,
    opencodeCommand: source.OPENCODE_COMMAND,
    opencodeHost: source.OPENCODE_HOST,
    opencodeStartPort: Number.isInteger(source.OPENCODE_START_PORT) && source.OPENCODE_START_PORT > 0 ? source.OPENCODE_START_PORT : OPENCODE_START_PORT,
    opencodeProviderId: source.OPENCODE_PROVIDER_ID,
    opencodeModelId: source.OPENCODE_MODEL_ID,
    requestTimeoutMs: Number.isInteger(source.REQUEST_TIMEOUT_MS) && source.REQUEST_TIMEOUT_MS > 0 ? source.REQUEST_TIMEOUT_MS : REQUEST_TIMEOUT_MS,
  };
}

async function writeSetupConfig(request: SetupSaveRequestMessage): Promise<{ ok: boolean; message?: string }> {
  const controlPlaneUrl = request.u.trim();
  if (!controlPlaneUrl) {
    return { ok: false, message: "invalid_control_plane_url" };
  }
  if (!/^wss?:\/\//.test(controlPlaneUrl)) {
    return { ok: false, message: "invalid_control_plane_url" };
  }

  const existing = (await readDotenvFile(ENV_FILE_PATH)) ?? {};
  const incomingToken = request.a.trim();
  const existingToken = (existing.AGENT_AUTH_TOKEN ?? process.env.AGENT_AUTH_TOKEN ?? "").trim();
  const agentAuthToken = incomingToken || existingToken;
  if (!agentAuthToken) {
    return { ok: false, message: "invalid_agent_auth_token" };
  }

  const merged: Record<string, string> = {
    ...existing,
    CONTROL_PLANE_URL: controlPlaneUrl,
    AGENT_AUTH_TOKEN: agentAuthToken,
    OPENCODE_COMMAND: (request.oc ?? existing.OPENCODE_COMMAND ?? OPENCODE_COMMAND).trim(),
    OPENCODE_HOST: (request.oh ?? existing.OPENCODE_HOST ?? OPENCODE_HOST).trim(),
    OPENCODE_START_PORT: String(request.os ?? parseInt(existing.OPENCODE_START_PORT ?? String(OPENCODE_START_PORT), 10)),
    OPENCODE_PROVIDER_ID: (request.op ?? existing.OPENCODE_PROVIDER_ID ?? OPENCODE_PROVIDER_ID).trim(),
    OPENCODE_MODEL_ID: (request.om ?? existing.OPENCODE_MODEL_ID ?? OPENCODE_MODEL_ID).trim(),
    REQUEST_TIMEOUT_MS: String(request.rt ?? parseInt(existing.REQUEST_TIMEOUT_MS ?? String(REQUEST_TIMEOUT_MS), 10)),
  };

  try {
    await writeDotenvFile(ENV_FILE_PATH, merged);
    await ensureEnvIgnored(ALLOWED_PROJECT_ROOT_REAL);
    loadDotenv({ path: ENV_FILE_PATH, override: true });
    return { ok: true, message: "saved_restart_required" };
  } catch {
    return { ok: false, message: "setup_save_failed" };
  }
}

async function acquireDaemonLock(): Promise<boolean> {
  const lockPayload = JSON.stringify(
    {
      pid: process.pid,
      deviceId: DEVICE_ID,
      root: ALLOWED_PROJECT_ROOT_REAL,
      startedAt: Date.now(),
    },
    null,
    2,
  );

  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      await writeFile(DAEMON_LOCK_FILE, `${lockPayload}\n`, { encoding: "utf8", flag: "wx" });
      daemonLockHeld = true;
      return true;
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error ? String((error as { code: unknown }).code) : "";
      if (code !== "EEXIST") {
        log(`failed to acquire daemon lock: ${code || "unknown"}`);
        return false;
      }

      const existing = await readExistingLockPid();
      if (existing > 0 && isProcessAlive(existing)) {
        log(`another daemon is already running on this device pid=${existing}`);
        return false;
      }

      await unlink(DAEMON_LOCK_FILE).catch(() => {
      });
    }
  }

  log("unable to acquire daemon lock after retries");
  return false;
}

async function releaseDaemonLock(): Promise<void> {
  if (!daemonLockHeld) {
    return;
  }
  const existing = await readExistingLockPid();
  if (existing === process.pid) {
    await unlink(DAEMON_LOCK_FILE).catch(() => {
    });
  }
  daemonLockHeld = false;
}

async function readExistingLockPid(): Promise<number> {
  try {
    const raw = await readFile(DAEMON_LOCK_FILE, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (!isObject(parsed)) {
      return 0;
    }
    const pid = parsed.pid;
    if (!isInteger(pid) || pid <= 0) {
      return 0;
    }
    return pid;
  } catch {
    return 0;
  }
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function redactSensitiveText(value: string): string {
  let output = value;
  const secrets = collectSensitiveValues();
  for (const secret of secrets) {
    output = output.split(secret).join("***REDACTED***");
  }
  output = output.replace(/\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|AUTH|API_KEY)[A-Z0-9_]*)\s*=\s*([^\s]+)/gi, "$1=***REDACTED***");
  output = output.replace(/"([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|AUTH|API_KEY)[A-Z0-9_]*)"\s*:\s*"[^"]*"/gi, '"$1":"***REDACTED***"');
  return output;
}

function collectSensitiveValues(): string[] {
  const values = new Set<string>();
  for (const secret of runtimeSensitiveValues) {
    values.add(secret);
  }
  if (AGENT_AUTH_TOKEN) {
    values.add(AGENT_AUTH_TOKEN);
  }
  for (const [key, value] of Object.entries(process.env)) {
    if (!value || value.length < 6) {
      continue;
    }
    if (/(TOKEN|SECRET|PASSWORD|AUTH|API_KEY)/i.test(key)) {
      values.add(value);
    }
  }
  return Array.from(values).sort((left, right) => right.length - left.length);
}

function log(message: string): void {
  process.stdout.write(`[agent-daemon] ${new Date().toISOString()} ${redactSensitiveText(message)}\n`);
}

function appendContinuityLog(source: "opencode" | "git" | "session", message: string): void {
  if (!message || !opencodeOrchestrator) {
    return;
  }
  opencodeOrchestrator.appendContinuityRecord(source, message);
}

function shutdown(): void {
  stopping = true;
  clearLifecycleTimers();
  clearTimer(reconnectTimer);
  reconnectTimer = null;
  opencodeOrchestrator?.shutdown();
  opencodeOrchestrator = null;
  void releaseDaemonLock();
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.close(1000, "shutdown");
  }
}

function clearLifecycleTimers(): void {
  clearTimer(telemetryTimer);
  clearTimer(watchdogTimer);
  clearTimer(portScanTimer);
  telemetryTimer = null;
  watchdogTimer = null;
  portScanTimer = null;
}

class OpenCodeOrchestrator {
  private readonly fallbackClient: OpenCodeClient;
  private readonly serversByFolder = new Map<string, ManagedOpenCodeServer>();
  private readonly sessionsToFolder = new Map<string, string>();
  private readonly jitBySession = new Map<string, SessionJitBinding>();
  private readonly sessionRegistry: SessionRegistry;
  private readonly sessionLogStore: SessionLogStore;
  private readonly sessionSnapshotStore: SessionSnapshotStore;
  private readonly bootstrapPromise: Promise<void>;

  constructor(
    private readonly projectRoot: string,
    private readonly timeoutMs: number,
  ) {
    this.fallbackClient = new OpenCodeClient(OPENCODE_BASE_URL, timeoutMs);
    this.sessionRegistry = new SessionRegistry(OPENCODE_REGISTRY_FILE);
    this.sessionLogStore = new SessionLogStore(SESSION_LOG_FILE, SESSION_LOG_MAX_BYTES);
    this.sessionSnapshotStore = new SessionSnapshotStore(SESSION_SNAPSHOT_FILE, SESSION_SNAPSHOT_MAX_BYTES);
    this.bootstrapPromise = this.bootstrapFromRegistry();
  }

  async initSession(sessionId: string, folderPath: string, jitCredential?: SessionJitCredential): Promise<OpenCodeSessionResult> {
    await this.bootstrapPromise;
    const resolvedFolderPath = await this.resolveAndValidateFolderPath(folderPath);
    if (!resolvedFolderPath) {
      return { ok: false, message: "invalid_folder_path" };
    }

    if (jitCredential && !isJitCredentialUsable(jitCredential)) {
      return { ok: false, message: "invalid_jit_credential" };
    }

    const serverResult = await this.getOrStartServer(resolvedFolderPath, jitCredential);
    if (!serverResult.server) {
      return { ok: false, message: serverResult.message ?? "opencode_down" };
    }

    const result = await serverResult.server.client.initSession(sessionId, resolvedFolderPath);
    if (result.ok) {
      const effectiveSessionId = result.sessionId ?? sessionId;
      this.sessionsToFolder.set(effectiveSessionId, resolvedFolderPath);
      if (jitCredential) {
        this.bindSessionJit(effectiveSessionId, resolvedFolderPath, serverResult.server, jitCredential);
      }
      const editorUrl = buildEditorUrl(serverResult.server.baseUrl, resolvedFolderPath, effectiveSessionId);
      serverResult.server.sessionUrl = editorUrl;
      void this.recordSessionMetadata(effectiveSessionId, resolvedFolderPath, serverResult.server);
      await this.persistRegistrySnapshot();
      return {
        ...result,
        uiUrl: editorUrl,
      };
    }

    if (result.message === "opencode_down" || result.message === "opencode_timeout") {
      this.stopServer(serverResult.server, "request_failure");
      const restarted = await this.getOrStartServer(resolvedFolderPath, jitCredential);
      if (!restarted.server) {
        return { ok: false, message: restarted.message ?? result.message };
      }
      const retried = await restarted.server.client.initSession(sessionId, resolvedFolderPath);
      if (retried.ok) {
        const effectiveSessionId = retried.sessionId ?? sessionId;
        this.sessionsToFolder.set(effectiveSessionId, resolvedFolderPath);
        if (jitCredential) {
          this.bindSessionJit(effectiveSessionId, resolvedFolderPath, restarted.server, jitCredential);
        }
        const editorUrl = buildEditorUrl(restarted.server.baseUrl, resolvedFolderPath, effectiveSessionId);
        restarted.server.sessionUrl = editorUrl;
        void this.recordSessionMetadata(effectiveSessionId, resolvedFolderPath, restarted.server);
        await this.persistRegistrySnapshot();
        return {
          ...retried,
          uiUrl: editorUrl,
        };
      }
      return retried;
    }

    return result;
  }

  async getSessionStatus(folderPath: string): Promise<OpenCodeSessionStatus> {
    await this.bootstrapPromise;

    const resolvedFolderPath = await this.resolveAndValidateFolderPath(folderPath);
    if (!resolvedFolderPath) {
      return { ok: false, message: "invalid_folder_path" };
    }

    const server = this.serversByFolder.get(resolvedFolderPath);
    if (!server) {
      return { ok: false, message: "not_running" };
    }

    const running = await this.isServerActive(server);
    if (!running) {
      this.unregisterServer(resolvedFolderPath);
      await this.persistRegistrySnapshot();
      return { ok: false, message: "not_running" };
    }

    return {
      ok: true,
      port: server.port,
      pid: server.pid,
      sessionUrl: normalizeEditorUrl(server.baseUrl, resolvedFolderPath, server.sessionUrl),
    };
  }

  async terminateSession(sessionId: string): Promise<OpenCodeSessionResult> {
    await this.bootstrapPromise;
    const clients = this.candidateClientsForSession(sessionId);
    let fallbackFailure: OpenCodeSessionResult = { ok: false, message: "opencode_down" };

    for (const candidate of clients) {
      const result = await candidate.client.terminateSession(sessionId, candidate.folderPath);
      if (result.ok) {
        this.sessionsToFolder.delete(sessionId);
        await this.clearSessionJit(sessionId, "session_terminated");
        return result;
      }
      if (result.message && result.message !== "opencode_down" && result.message !== "opencode_timeout") {
        fallbackFailure = result;
      }
    }

    return fallbackFailure;
  }

  shutdown(): void {
    for (const binding of this.jitBySession.values()) {
      clearTimeout(binding.timer);
    }
    this.jitBySession.clear();
    for (const server of this.serversByFolder.values()) {
      if (server.process && server.process.exitCode === null && !server.process.killed) {
        server.process.kill();
      }
    }
    this.serversByFolder.clear();
    this.sessionsToFolder.clear();
    void this.persistRegistrySnapshot();
  }

  async handleControlPlaneReconnect(): Promise<void> {
    await this.bootstrapPromise;
    await this.sessionLogStore.warmRecentLines(SESSION_LOG_REPLAY_LINES);
    await this.sessionSnapshotStore.warmRecentLines(SESSION_LOG_REPLAY_LINES);
  }

  appendContinuityRecord(source: "opencode" | "git" | "session", text: string): void {
    if (!text) {
      return;
    }
    void this.sessionLogStore.appendLine(source, text);
    const sessionId = this.findLikelySessionIdForMessage(source);
    void this.sessionSnapshotStore.appendEvent({
      ts: new Date().toISOString(),
      k: "log",
      src: source,
      m: truncateText(text, 4000),
      ...(sessionId ? { sid: sessionId } : {}),
    });
  }

  isManagedOpenCodePort(port: number): boolean {
    for (const server of this.serversByFolder.values()) {
      if (server.port === port) {
        return true;
      }
    }
    return false;
  }

  hasActiveSessions(): boolean {
    return this.sessionsToFolder.size > 0;
  }

  async revokeJitCredentials(options: { sessionId?: string; credentialRef?: string; reason: string }): Promise<number> {
    await this.bootstrapPromise;
    const targets = new Set<string>();
    if (options.sessionId) {
      targets.add(options.sessionId);
    }
    if (options.credentialRef) {
      for (const [sessionId, binding] of this.jitBySession.entries()) {
        if (binding.credentialRef === options.credentialRef) {
          targets.add(sessionId);
        }
      }
    }
    if (!options.sessionId && !options.credentialRef) {
      for (const sessionId of this.jitBySession.keys()) {
        targets.add(sessionId);
      }
    }

    let affected = 0;
    for (const sessionId of targets) {
      const binding = this.jitBySession.get(sessionId);
      if (binding) {
        affected += 1;
      }
      const termination = await this.terminateSession(sessionId);
      if (!termination.ok && binding) {
        const server = this.serversByFolder.get(binding.folderPath);
        if (server) {
          this.stopServer(server, `jit_killswitch_${singleLine(options.reason)}`);
        }
        await this.clearSessionJit(sessionId, "kill_switch_force");
      }
    }

    if (options.credentialRef) {
      for (const server of this.serversByFolder.values()) {
        if (server.jitCredentialRef === options.credentialRef) {
          this.stopServer(server, `jit_ref_revoked_${options.credentialRef}`);
        }
      }
    }

    return affected;
  }

  async readSessionLogTailLines(limit: number): Promise<string[]> {
    await this.bootstrapPromise;
    return this.sessionSnapshotStore.readLastLines(limit);
  }

  private bindSessionJit(sessionId: string, folderPath: string, server: ManagedOpenCodeServer, credential: SessionJitCredential): void {
    const previous = this.jitBySession.get(sessionId);
    if (previous) {
      clearTimeout(previous.timer);
      this.jitBySession.delete(sessionId);
    }
    const credentialRef = credential.r ?? fingerprintJitCredential(credential);
    const timerMs = Math.max(0, credential.e - Date.now());
    const timer = setTimeout(() => {
      void this.handleJitExpiry(sessionId, credentialRef);
    }, timerMs);
    timer.unref();

    this.jitBySession.set(sessionId, {
      sessionId,
      folderPath,
      credentialRef,
      expiresAt: credential.e,
      envVarName: credential.n ?? SESSION_JIT_DEFAULT_ENV_VAR,
      extraEnv: Array.isArray(credential.v) ? credential.v.map(([name]) => name) : [],
      timer,
    });

    server.jitCredentialRef = credentialRef;
    server.jitCredentialExpiry = credential.e;
    server.jitCredentialFingerprint = fingerprintJitCredential(credential);
  }

  private async handleJitExpiry(sessionId: string, credentialRef: string): Promise<void> {
    const binding = this.jitBySession.get(sessionId);
    if (!binding || binding.credentialRef !== credentialRef) {
      return;
    }
    appendContinuityLog("session", `jit_expired session=${sessionId} ref=${credentialRef}`);
    await this.revokeJitCredentials({ sessionId, credentialRef, reason: "jit_expired" });
  }

  private async clearSessionJit(sessionId: string, reason: string): Promise<void> {
    const binding = this.jitBySession.get(sessionId);
    if (!binding) {
      return;
    }

    clearTimeout(binding.timer);
    this.jitBySession.delete(sessionId);
    appendContinuityLog("session", `jit_cleared session=${sessionId} reason=${singleLine(reason)}`);

    const server = this.serversByFolder.get(binding.folderPath);
    if (!server) {
      return;
    }

    let hasRemainingJit = false;
    for (const active of this.jitBySession.values()) {
      if (active.folderPath === binding.folderPath) {
        hasRemainingJit = true;
        break;
      }
    }

    if (!hasRemainingJit && (server.jitCredentialFingerprint || server.jitCredentialRef)) {
      this.stopServer(server, `jit_cleanup_${singleLine(reason)}`);
    }
  }

  private async recordSessionMetadata(sessionId: string, folderPath: string, server: ManagedOpenCodeServer): Promise<void> {
    const metadata = captureSessionMetadata(folderPath, server.jitCredentialExpiry);
    await this.sessionSnapshotStore.appendEvent({
      ts: new Date().toISOString(),
      k: "meta",
      sid: sessionId,
      fp: folderPath,
      md: metadata,
    });
  }

  private findLikelySessionIdForMessage(source: "opencode" | "git" | "session"): string | undefined {
    if (this.sessionsToFolder.size === 0) {
      return undefined;
    }
    const entries = Array.from(this.sessionsToFolder.keys());
    if (source === "session") {
      return entries[entries.length - 1];
    }
    return entries[0];
  }

  private async bootstrapFromRegistry(): Promise<void> {
    const entries = await this.sessionRegistry.readAll();
    for (const entry of entries) {
      if (!this.isPidAlive(entry.pid)) {
        continue;
      }

      const baseUrl = `http://${OPENCODE_HOST}:${entry.port}`;
      const server: ManagedOpenCodeServer = {
        folderPath: entry.folderPath,
        baseUrl,
        port: entry.port,
        pid: entry.pid,
        process: null,
        client: new OpenCodeClient(baseUrl, this.timeoutMs),
        sessionUrl: normalizeEditorUrl(baseUrl, entry.folderPath, entry.sessionUrl),
      };

      if (await this.isServerReachable(baseUrl)) {
        this.serversByFolder.set(entry.folderPath, server);
      }
    }

    await this.persistRegistrySnapshot();
  }

  private async resolveAndValidateFolderPath(folderPath: string): Promise<string | null> {
    const safePath = sanitizeRelativePath(folderPath);
    if (!safePath) {
      return null;
    }

    const targetPath = path.resolve(this.projectRoot, safePath);
    try {
      const rootRealPath = await realpath(this.projectRoot);
      const targetRealPath = await realpath(targetPath);
      if (!isPathWithinRoot(rootRealPath, targetRealPath)) {
        return null;
      }
      const targetStat = await lstat(targetRealPath);
      if (!targetStat.isDirectory()) {
        return null;
      }
      return targetRealPath;
    } catch {
      return null;
    }
  }

  private async getOrStartServer(folderPath: string, jitCredential?: SessionJitCredential): Promise<{ server?: ManagedOpenCodeServer; message?: string }> {
    const existing = this.serversByFolder.get(folderPath);
    const requestedFingerprint = jitCredential ? fingerprintJitCredential(jitCredential) : undefined;
    if (existing) {
      if (existing.starting) {
        const isReady = await existing.starting;
        if (isReady && this.serversByFolder.get(folderPath) === existing) {
          if (!requestedFingerprint || existing.jitCredentialFingerprint === requestedFingerprint) {
            return { server: existing };
          }
        }
      } else if (await this.isServerActive(existing)) {
        if (!requestedFingerprint || existing.jitCredentialFingerprint === requestedFingerprint) {
          return { server: existing };
        }
        this.stopServer(existing, "jit_credential_rotated");
        return this.startServer(folderPath, jitCredential);
      }
      this.stopServer(existing, "stale_or_unreachable");
    }

    return this.startServer(folderPath, jitCredential);
  }

  private async startServer(folderPath: string, jitCredential?: SessionJitCredential): Promise<{ server?: ManagedOpenCodeServer; message?: string }> {
    const port = await findAvailablePort(OPENCODE_START_PORT, OPENCODE_PORT_SCAN_RANGE, OPENCODE_HOST);
    if (!port) {
      return { message: "opencode_port_unavailable" };
    }

    const args = ["serve", "--hostname", OPENCODE_HOST, "--port", String(port), "--print-logs"];
    let child: ChildProcess;
    try {
      child = spawn(OPENCODE_COMMAND, args, {
        cwd: folderPath,
        env: buildOpencodeSpawnEnv(jitCredential),
        stdio: ["ignore", "pipe", "pipe"],
        shell: process.platform === "win32",
      });
    } catch {
      return { message: "opencode_spawn_failed" };
    }

    const baseUrl = `http://${OPENCODE_HOST}:${port}`;
    const server: ManagedOpenCodeServer = {
      folderPath,
      baseUrl,
      port,
      pid: child.pid ?? -1,
      process: child,
      client: new OpenCodeClient(baseUrl, this.timeoutMs),
      sessionUrl: baseUrl,
      ...(jitCredential
        ? {
            jitCredentialFingerprint: fingerprintJitCredential(jitCredential),
            jitCredentialRef: jitCredential.r ?? fingerprintJitCredential(jitCredential),
            jitCredentialExpiry: jitCredential.e,
          }
        : {}),
    };
    if (server.pid <= 0) {
      this.stopServer(server, "spawn_missing_pid");
      return { message: "opencode_spawn_failed" };
    }

    server.process?.stdout?.on("data", (chunk) => {
      this.handleOpenCodeLog(server, String(chunk));
    });
    server.process?.stderr?.on("data", (chunk) => {
      this.handleOpenCodeLog(server, String(chunk));
    });
    server.process?.on("exit", (code, signal) => {
      const knownServer = this.serversByFolder.get(folderPath);
      if (knownServer === server) {
        this.unregisterServer(folderPath);
        void this.persistRegistrySnapshot();
      }
      log(`opencode exited port=${server.port} code=${code ?? "null"} signal=${signal ?? "null"}`);
    });

    this.serversByFolder.set(folderPath, server);
    await this.persistRegistrySnapshot();
    log(`starting opencode port=${port} folder=${folderPath}`);
    const readyPromise = this.waitUntilReachable(server);
    server.starting = readyPromise;

    const ready = await readyPromise;
    if (!ready) {
      this.stopServer(server, "startup_timeout");
      return { message: "opencode_start_timeout" };
    }

    delete server.starting;
    await this.persistRegistrySnapshot();
    return { server };
  }

  private async waitUntilReachable(server: ManagedOpenCodeServer): Promise<boolean> {
    const deadline = Date.now() + OPENCODE_BOOT_TIMEOUT_MS;
    let delayMs = Math.max(100, OPENCODE_READY_CHECK_MS);
    while (Date.now() < deadline) {
      if (!server.process || server.process.exitCode !== null) {
        return false;
      }
      if (await this.isServerReachable(server.baseUrl)) {
        return true;
      }
      await sleep(delayMs);
      delayMs = Math.min(1000, delayMs * 2);
    }
    return false;
  }

  private async isServerReachable(baseUrl: string): Promise<boolean> {
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, Math.min(1500, this.timeoutMs));
    timeout.unref();

    try {
      await fetch(`${baseUrl}/health`, {
        method: "GET",
        signal: controller.signal,
      });
      return true;
    } catch {
      return false;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async isServerActive(server: ManagedOpenCodeServer): Promise<boolean> {
    if (!this.isPidAlive(server.pid)) {
      return false;
    }
    return this.isServerReachable(server.baseUrl);
  }

  private handleOpenCodeLog(server: ManagedOpenCodeServer, rawChunk: string): void {
    const sanitizedChunk = redactSensitiveText(rawChunk);

    const text = sanitizedChunk.trim();
    if (!text) {
      return;
    }
    this.appendContinuityRecord("opencode", text);
    log(`opencode(${server.port}) ${text}`);

    const matchedSessionUrl = extractSessionUrlFromLog(text);
    if (matchedSessionUrl && matchedSessionUrl !== server.sessionUrl) {
      server.sessionUrl = matchedSessionUrl;
      void this.persistRegistrySnapshot();
    }
  }

  private stopServer(server: ManagedOpenCodeServer, reason: string): void {
    const knownServer = this.serversByFolder.get(server.folderPath);
    if (knownServer !== server) {
      return;
    }
    this.unregisterServer(server.folderPath);
    if (server.process && server.process.exitCode === null && !server.process.killed) {
      server.process.kill();
    }
    void this.persistRegistrySnapshot();
    log(`stopping opencode port=${server.port} reason=${reason}`);
  }

  private unregisterServer(folderPath: string): void {
    const server = this.serversByFolder.get(folderPath);
    if (!server) {
      return;
    }
    this.serversByFolder.delete(folderPath);
    for (const [sessionId, sessionFolderPath] of this.sessionsToFolder.entries()) {
      if (sessionFolderPath === folderPath) {
        this.sessionsToFolder.delete(sessionId);
      }
    }
    for (const [sessionId, binding] of this.jitBySession.entries()) {
      if (binding.folderPath !== folderPath) {
        continue;
      }
      clearTimeout(binding.timer);
      this.jitBySession.delete(sessionId);
    }
  }

  private candidateClientsForSession(sessionId: string): Array<{ baseUrl: string; client: OpenCodeClient; folderPath?: string }> {
    const seenBaseUrls = new Set<string>();
    const clients: Array<{ baseUrl: string; client: OpenCodeClient; folderPath?: string }> = [];

    const mappedFolder = this.sessionsToFolder.get(sessionId);
    if (mappedFolder) {
      const mappedServer = this.serversByFolder.get(mappedFolder);
      if (mappedServer) {
        seenBaseUrls.add(mappedServer.baseUrl);
        clients.push({ baseUrl: mappedServer.baseUrl, client: mappedServer.client, folderPath: mappedServer.folderPath });
      }
    }

    for (const server of this.serversByFolder.values()) {
      if (seenBaseUrls.has(server.baseUrl)) {
        continue;
      }
      seenBaseUrls.add(server.baseUrl);
      clients.push({ baseUrl: server.baseUrl, client: server.client, folderPath: server.folderPath });
    }

    if (!seenBaseUrls.has(OPENCODE_BASE_URL)) {
      clients.push({ baseUrl: OPENCODE_BASE_URL, client: this.fallbackClient });
    }

    return clients;
  }

  private async persistRegistrySnapshot(): Promise<void> {
    const entries: SessionRegistryEntry[] = [];
    for (const server of this.serversByFolder.values()) {
      if (!this.isPidAlive(server.pid)) {
        continue;
      }
      entries.push({
        folderPath: server.folderPath,
        port: server.port,
        pid: server.pid,
        sessionUrl: server.sessionUrl,
      });
    }
    await this.sessionRegistry.writeAll(entries);
  }

  private isPidAlive(pid: number): boolean {
    return isProcessAlive(pid);
  }
}

type ManagedOpenCodeServer = {
  folderPath: string;
  baseUrl: string;
  port: number;
  pid: number;
  process: ChildProcess | null;
  client: OpenCodeClient;
  sessionUrl: string;
  jitCredentialFingerprint?: string;
  jitCredentialRef?: string;
  jitCredentialExpiry?: number;
  starting?: Promise<boolean>;
};

type SessionJitBinding = {
  sessionId: string;
  folderPath: string;
  credentialRef: string;
  expiresAt: number;
  envVarName: string;
  extraEnv: string[];
  timer: NodeJS.Timeout;
};

type OpenCodeSessionStatus = {
  ok: boolean;
  port?: number;
  pid?: number;
  sessionUrl?: string;
  message?: string;
};

type SetupConfigStatus = {
  ok: boolean;
  configured?: boolean;
  controlPlaneUrl?: string;
  hasAgentAuthToken?: boolean;
  opencodeCommand?: string;
  opencodeHost?: string;
  opencodeStartPort?: number;
  opencodeProviderId?: string;
  opencodeModelId?: string;
  requestTimeoutMs?: number;
  message?: string;
};

type SessionRegistryEntry = {
  folderPath: string;
  port: number;
  pid: number;
  sessionUrl: string;
};

class SessionRegistry {
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  async readAll(): Promise<SessionRegistryEntry[]> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as unknown;
      if (!Array.isArray(parsed)) {
        return [];
      }
      const entries: SessionRegistryEntry[] = [];
      for (const item of parsed) {
        if (!isObject(item)) {
          continue;
        }
        if (typeof item.folderPath !== "string" || item.folderPath.length === 0) {
          continue;
        }
        if (!isInteger(item.port) || item.port < 1 || item.port > 65535) {
          continue;
        }
        if (!isInteger(item.pid) || item.pid <= 0) {
          continue;
        }
        const sessionUrl = typeof item.sessionUrl === "string" && item.sessionUrl.length > 0
          ? item.sessionUrl
          : `http://${OPENCODE_HOST}:${item.port}`;
        entries.push({
          folderPath: item.folderPath,
          port: item.port,
          pid: item.pid,
          sessionUrl,
        });
      }
      return entries;
    } catch {
      return [];
    }
  }

  async writeAll(entries: SessionRegistryEntry[]): Promise<void> {
    this.writeQueue = this.writeQueue
      .catch(() => {
      })
      .then(async () => {
        const normalized = entries
          .map((entry) => ({
            folderPath: entry.folderPath,
            port: entry.port,
            pid: entry.pid,
            sessionUrl: entry.sessionUrl,
          }))
          .sort((left, right) => left.folderPath.localeCompare(right.folderPath));
        await mkdir(path.dirname(this.filePath), { recursive: true });
        await writeFile(this.filePath, `${JSON.stringify(normalized, null, 2)}\n`, "utf8");
      });

    await this.writeQueue;
  }
}

type SessionSnapshotEntry = {
  ts: string;
  k: "meta" | "log";
  sid?: string;
  fp?: string;
  src?: "opencode" | "git" | "session";
  m?: string;
  md?: SessionSnapshotMetadata;
};

class SessionSnapshotStore {
  private writeQueue: Promise<void> = Promise.resolve();
  private recentLines: string[] = [];
  private readonly maxRecentLines = SESSION_LOG_REPLAY_MAX_LINES * 8;
  private hiddenFileEnsured = false;

  constructor(
    private readonly filePath: string,
    private readonly maxBytes: number,
  ) {}

  async appendEvent(entry: SessionSnapshotEntry): Promise<void> {
    const line = JSON.stringify(entry);
    this.writeQueue = this.writeQueue
      .catch(() => {
      })
      .then(async () => {
        await mkdir(path.dirname(this.filePath), { recursive: true });
        await appendFile(this.filePath, `${line}\n`, "utf8");
        await this.ensureHiddenFile();
        this.rememberLines([line]);
        await this.enforceMaxSize();
      });
    await this.writeQueue;
  }

  async warmRecentLines(limit: number): Promise<void> {
    const lineLimit = clampInt(limit, 1, SESSION_LOG_REPLAY_MAX_LINES);
    await this.writeQueue.catch(() => {
    });
    if (this.recentLines.length >= lineLimit) {
      return;
    }
    const diskLines = await this.readLastLinesFromDisk(lineLimit);
    this.rememberLines(diskLines);
  }

  async readLastLines(limit: number): Promise<string[]> {
    const lineLimit = clampInt(limit, 1, SESSION_LOG_REPLAY_MAX_LINES);
    await this.writeQueue.catch(() => {
    });
    if (this.recentLines.length >= lineLimit) {
      return this.recentLines.slice(-lineLimit);
    }
    const diskLines = await this.readLastLinesFromDisk(lineLimit);
    this.rememberLines(diskLines);
    return diskLines;
  }

  private rememberLines(lines: string[]): void {
    if (lines.length === 0) {
      return;
    }
    this.recentLines.push(...lines);
    if (this.recentLines.length > this.maxRecentLines) {
      this.recentLines = this.recentLines.slice(-this.maxRecentLines);
    }
  }

  private async readLastLinesFromDisk(limit: number): Promise<string[]> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const lines = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
      if (lines.length > 0 && lines[lines.length - 1] === "") {
        lines.pop();
      }
      return lines.slice(-limit);
    } catch {
      return [];
    }
  }

  private async enforceMaxSize(): Promise<void> {
    if (this.maxBytes <= 0) {
      return;
    }
    try {
      const fileStat = await stat(this.filePath);
      if (fileStat.size <= this.maxBytes) {
        return;
      }
      const trimmedLines = await trimFileToMaxBytes(this.filePath, this.maxBytes);
      if (trimmedLines) {
        this.recentLines = trimmedLines.slice(-this.maxRecentLines);
      }
    } catch {
    }
  }

  private async ensureHiddenFile(): Promise<void> {
    if (this.hiddenFileEnsured || process.platform !== "win32") {
      return;
    }
    this.hiddenFileEnsured = true;
    await setWindowsHiddenAttribute(this.filePath).catch(() => {
    });
  }
}

class SessionLogStore {
  private writeQueue: Promise<void> = Promise.resolve();
  private recentLines: string[] = [];
  private readonly maxRecentLines = SESSION_LOG_REPLAY_MAX_LINES * 8;

  constructor(
    private readonly filePath: string,
    private readonly maxBytes: number,
  ) {}

  async appendLine(source: "opencode" | "git" | "session", rawChunk: string): Promise<void> {
    if (!rawChunk.trim()) {
      return;
    }
    const normalized = rawChunk.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const baseTimestamp = new Date().toISOString();
    const lines = normalized
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line) => `[${baseTimestamp}] ${source}: ${truncateText(line, 2000)}`);
    if (lines.length === 0) {
      return;
    }

    this.writeQueue = this.writeQueue
      .catch(() => {
      })
      .then(async () => {
        await mkdir(path.dirname(this.filePath), { recursive: true });
        await appendFile(this.filePath, `${lines.join("\n")}\n`, "utf8");
        this.rememberLines(lines);
        await this.enforceMaxSize();
      });
    await this.writeQueue;
  }

  async warmRecentLines(limit: number): Promise<void> {
    const lineLimit = clampInt(limit, 1, SESSION_LOG_REPLAY_MAX_LINES);
    await this.writeQueue.catch(() => {
    });
    if (this.recentLines.length >= lineLimit) {
      return;
    }
    const diskLines = await this.readLastLinesFromDisk(lineLimit);
    this.rememberLines(diskLines);
  }

  async readLastLines(limit: number): Promise<string[]> {
    const lineLimit = clampInt(limit, 1, SESSION_LOG_REPLAY_MAX_LINES);
    await this.writeQueue.catch(() => {
    });
    if (this.recentLines.length >= lineLimit) {
      return this.recentLines.slice(-lineLimit);
    }
    const diskLines = await this.readLastLinesFromDisk(lineLimit);
    this.rememberLines(diskLines);
    return diskLines;
  }

  private rememberLines(lines: string[]): void {
    if (lines.length === 0) {
      return;
    }
    this.recentLines.push(...lines);
    if (this.recentLines.length > this.maxRecentLines) {
      this.recentLines = this.recentLines.slice(-this.maxRecentLines);
    }
  }

  private async readLastLinesFromDisk(limit: number): Promise<string[]> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const lines = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
      if (lines.length > 0 && lines[lines.length - 1] === "") {
        lines.pop();
      }
      return lines.slice(-limit);
    } catch {
      return [];
    }
  }

  private async enforceMaxSize(): Promise<void> {
    if (this.maxBytes <= 0) {
      return;
    }
    try {
      const fileStat = await stat(this.filePath);
      if (fileStat.size <= this.maxBytes) {
        return;
      }
      const trimmedLines = await trimFileToMaxBytes(this.filePath, this.maxBytes);
      if (trimmedLines) {
        this.recentLines = trimmedLines.slice(-this.maxRecentLines);
      }
    } catch {
    }
  }
}

async function trimFileToMaxBytes(filePath: string, maxBytes: number): Promise<string[] | null> {
  const rawBuffer = await readFile(filePath);
  if (rawBuffer.byteLength <= maxBytes) {
    return null;
  }

  const tail = rawBuffer.subarray(Math.max(0, rawBuffer.byteLength - maxBytes));
  const lineStart = tail.indexOf(0x0a);
  const trimmedBuffer = lineStart >= 0 ? tail.subarray(lineStart + 1) : tail;
  await writeFile(filePath, trimmedBuffer);

  const lines = trimmedBuffer
    .toString("utf8")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

async function setWindowsHiddenAttribute(filePath: string): Promise<void> {
  if (process.platform !== "win32") {
    return;
  }

  await new Promise<void>((resolve) => {
    const child = spawn("attrib", ["+h", filePath], {
      stdio: "ignore",
      shell: false,
    });
    child.once("error", () => {
      resolve();
    });
    child.once("close", () => {
      resolve();
    });
  });
}

async function findAvailablePort(startPort: number, scanRange: number, host: string): Promise<number | null> {
  const firstPort = Math.max(1024, startPort);
  for (let offset = 0; offset < scanRange; offset += 1) {
    const candidate = firstPort + offset;
    const available = await isPortAvailable(candidate, host);
    if (available) {
      return candidate;
    }
  }
  return null;
}

function isPortAvailable(port: number, host: string): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer();
    let settled = false;

    const finish = (result: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(result);
    };

    server.once("error", () => {
      finish(false);
    });

    server.once("listening", () => {
      server.close(() => {
        finish(true);
      });
    });

    server.listen(port, host);
    server.unref();
  });
}

async function sleep(durationMs: number): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, durationMs);
  });
}

async function detectListeningPorts(): Promise<number[]> {
  const command = resolvePortScanCommand();
  if (!command) {
    return [];
  }

  try {
    const output = await captureCommandOutput(command.command, command.args, 5000);
    return parseListeningPortsFromOutput(output)
      .filter((port) => port >= 1024 && port <= 65535)
      .filter((port) => port !== OPENCODE_START_PORT)
      .slice(0, 256);
  } catch {
    return [];
  }
}

function resolvePortScanCommand(): { command: string; args: string[] } | null {
  if (process.platform === "win32") {
    return { command: "netstat", args: ["-ano", "-p", "tcp"] };
  }
  if (process.platform === "linux") {
    return { command: "ss", args: ["-ltnH"] };
  }
  if (process.platform === "darwin") {
    return { command: "lsof", args: ["-nP", "-iTCP", "-sTCP:LISTEN"] };
  }
  return null;
}

async function captureCommandOutput(command: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });

    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("command_timeout"));
    }, timeoutMs);
    timeout.unref();

    child.stdout?.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr?.on("data", (chunk) => {
      stderr += String(chunk);
    });

    child.on("close", (code) => {
      clearTimeout(timeout);
      if (code !== 0 && !stdout) {
        reject(new Error(singleLine(stderr || `command_exit_${code}`)));
        return;
      }
      resolve(stdout);
    });

    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

function parseListeningPortsFromOutput(raw: string): number[] {
  const ports = new Set<number>();
  const lines = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  for (const line of lines) {
    const normalized = line.trim();
    if (!normalized || !/LISTEN/i.test(normalized)) {
      continue;
    }
    const match = /(?:\[.*?\]|[A-Za-z0-9.*:_-]+):(\d{1,5})/.exec(normalized);
    if (!match) {
      continue;
    }
    const portText = match[1];
    if (!portText) {
      continue;
    }
    const port = parseInt(portText, 10);
    if (!Number.isInteger(port)) {
      continue;
    }
    ports.add(port);
  }
  return Array.from(ports).sort((left, right) => left - right);
}

function extractSessionUrlFromLog(logLine: string): string | null {
  const match = SESSION_URL_LOG_REGEX.exec(logLine);
  return match ? match[0] : null;
}

function buildEditorUrl(baseUrl: string, directoryPath: string, sessionId?: string): string {
  try {
    const url = new URL(baseUrl);
    const slug = encodeDirectorySlug(directoryPath);
    url.search = "";
    url.hash = "";
    if (sessionId) {
      url.pathname = `/${slug}/session/${encodeURIComponent(sessionId)}`;
    } else {
      url.pathname = `/${slug}`;
    }
    return url.toString();
  } catch {
    return baseUrl;
  }
}

function normalizeEditorUrl(baseUrl: string, directoryPath: string, sessionUrl?: string): string {
  const fallbackUrl = buildEditorUrl(baseUrl, directoryPath);
  if (!sessionUrl) {
    return fallbackUrl;
  }
  try {
    const parsed = new URL(sessionUrl);
    if (parsed.searchParams.has("directory")) {
      return fallbackUrl;
    }
    return parsed.toString();
  } catch {
    return fallbackUrl;
  }
}

function encodeDirectorySlug(directoryPath: string): string {
  return Buffer.from(directoryPath, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function appendDirectoryQuery(urlText: string, directoryPath?: string): string {
  if (!directoryPath) {
    return urlText;
  }
  try {
    const url = new URL(urlText);
    url.searchParams.set("directory", directoryPath);
    return url.toString();
  } catch {
    return urlText;
  }
}

class OpenCodeClient {
  constructor(
    private readonly baseUrl: string,
    private readonly timeoutMs: number,
  ) {}

  async initSession(sessionId: string, directoryPath?: string): Promise<OpenCodeSessionResult> {
    const initPayload = {
      modelID: OPENCODE_MODEL_ID,
      providerID: OPENCODE_PROVIDER_ID,
      messageID: `msg_${randomToken(12)}`,
    };

    const initResult = await this.postToCandidates(`/session/${encodeURIComponent(sessionId)}/init`, initPayload, directoryPath);
    if (initResult.ok) {
      return { ok: true, sessionId };
    }

    if (initResult.message === "opencode_down" || initResult.message === "opencode_timeout") {
      return initResult;
    }

    const createResult = await this.createSession(directoryPath);
    if (!createResult.ok) {
      return createResult;
    }

    const createdSessionId = readSessionIdFromPayload(createResult.payload);
    if (!createdSessionId) {
      return { ok: false, message: "opencode_invalid_session" };
    }
    return { ok: true, sessionId: createdSessionId };
  }

  terminateSession(sessionId: string, directoryPath?: string): Promise<OpenCodeSessionResult> {
    return this.postToCandidates(`/session/${encodeURIComponent(sessionId)}/abort`, undefined, directoryPath);
  }

  private async createSession(directoryPath?: string): Promise<OpenCodeSessionResult> {
    const withConfiguredModel = await this.postToCandidates("/session", {
      modelID: OPENCODE_MODEL_ID,
      providerID: OPENCODE_PROVIDER_ID,
    }, directoryPath);
    if (withConfiguredModel.ok || withConfiguredModel.message === "opencode_down" || withConfiguredModel.message === "opencode_timeout") {
      return withConfiguredModel;
    }

    return this.postToCandidates("/session", {}, directoryPath);
  }

  private async postToCandidates(endpointPath: string, body?: object, directoryPath?: string): Promise<OpenCodeSessionResult> {
    const candidateBaseUrls = this.resolveCandidateBaseUrls();

    for (let index = 0; index < candidateBaseUrls.length; index += 1) {
      const endpoint = appendDirectoryQuery(`${candidateBaseUrls[index]!}${endpointPath}`, directoryPath);
      const controller = new AbortController();
      const timeout = setTimeout(() => {
        controller.abort();
      }, this.timeoutMs);
      timeout.unref();

      try {
        const requestInit: RequestInit = {
          method: "POST",
          signal: controller.signal,
          headers: {
            "content-type": "application/json",
            accept: "application/json",
          },
          ...(body ? { body: JSON.stringify(body) } : {}),
        };
        const response = await fetch(endpoint, requestInit);
        const payload = await response.json().catch(() => undefined);
        if (response.ok) {
          return { ok: true, payload };
        }
        return { ok: false, message: toOpenCodeFailureMessage(response.status, payload), payload };
      } catch (error) {
        const isAbort = error instanceof DOMException && error.name === "AbortError";
        if (isAbort) {
          return { ok: false, message: "opencode_timeout" };
        }
        const hasAnotherCandidate = index < candidateBaseUrls.length - 1;
        if (!hasAnotherCandidate) {
          return { ok: false, message: "opencode_down" };
        }
      } finally {
        clearTimeout(timeout);
      }
    }

    return { ok: false, message: "opencode_down" };
  }

  private resolveCandidateBaseUrls(): string[] {
    const primary = this.baseUrl;
    try {
      const parsed = new URL(primary);
      if (parsed.hostname === "localhost") {
        const fallback = new URL(primary);
        fallback.hostname = "127.0.0.1";
        return [primary, fallback.toString().replace(/\/$/, "")];
      }
      if (parsed.hostname === "127.0.0.1") {
        const fallback = new URL(primary);
        fallback.hostname = "localhost";
        return [primary, fallback.toString().replace(/\/$/, "")];
      }
    } catch {
    }
    return [primary];
  }
}

type OpenCodeSessionResult = {
  ok: boolean;
  message?: string;
  sessionId?: string;
  payload?: unknown;
  uiUrl?: string;
};

function readSessionIdFromPayload(payload: unknown): string | null {
  if (!isObject(payload)) {
    return null;
  }
  const sessionId = payload.id;
  if (typeof sessionId !== "string") {
    return null;
  }
  return /^ses[A-Za-z0-9_-]{1,64}$/.test(sessionId) ? sessionId : null;
}

function toOpenCodeFailureMessage(statusCode: number, payload: unknown): string {
  const fallback = `http_${statusCode}`;
  if (!isObject(payload)) {
    return fallback;
  }

  if (typeof payload.name === "string" && payload.name.length > 0) {
    return fitSessionFailureReason(`${fallback}:${payload.name}`);
  }

  const errorList = payload.error;
  if (Array.isArray(errorList) && errorList.length > 0) {
    const first = errorList[0];
    if (isObject(first)) {
      const code = typeof first.code === "string" ? first.code : "";
      const pathValue = first.path;
      const pathSegment =
        Array.isArray(pathValue) && pathValue.length > 0 && typeof pathValue[0] === "string" ? pathValue[0] : "";
      const detail = [code, pathSegment].filter(Boolean).join(":");
      if (detail) {
        return fitSessionFailureReason(`${fallback}:${detail}`);
      }
    }
  }

  if (typeof payload.message === "string" && payload.message.length > 0) {
    return fitSessionFailureReason(`${fallback}:${payload.message}`);
  }

  return fallback;
}

function fitSessionFailureReason(reason: string): string {
  const trimmed = reason.trim();
  if (trimmed.length <= 96) {
    return trimmed;
  }
  return `${trimmed.slice(0, 93)}...`;
}

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
process.once("exit", () => {
  void releaseDaemonLock();
});

// CLI argument handling
const args = process.argv.slice(2);
const isSetupMode = args.includes("--setup") || args.includes("--configure-env");
const isHeadlessMode = process.env.RUNTIME_MODE === "headless" || !process.env.RUNTIME_MODE;
const isUiBoxMode = process.env.RUNTIME_MODE === "ui-box";

async function handleCliSetup(): Promise<void> {
  const provisioner = new Provisioner();
  
  // Probe dependencies first
  console.log("\n📦 Checking dependencies...");
  const deps = await provisioner.probeDependencies();
  
  const missingDeps = deps.filter(d => !d.installed);
  if (missingDeps.length > 0) {
    console.log("\n⚠️  Missing dependencies:");
    for (const dep of missingDeps) {
      console.log(`   - ${dep.type}: ${dep.error || "Not installed"}`);
    }
    console.log("\nPlease install the missing dependencies and try again.");
    console.log("Visit https://codemantle.cloud/docs/setup for installation instructions.");
    process.exit(1);
  }
  
  console.log("✅ All dependencies found:");
  for (const dep of deps) {
    console.log(`   - ${dep.type}: ${dep.version || "installed"}`);
  }
  
  // Run interactive setup
  console.log("\n🚀 Starting CodeMantle setup...\n");
  const config = await provisioner.runInteractiveSetup("headless");
  
  console.log("\n✨ Setup complete!");
  console.log(`\nWorkspace: ${config.workspacePath}`);
  console.log(`Control Plane: ${config.controlPlaneUrl}`);
  console.log(`Auto-start: ${config.startOnBoot ? "enabled" : "disabled"}`);
  console.log("\nRun 'codemantle-agent' to start the daemon.");
}

async function startDaemon(): Promise<void> {
  const runtimeConfig = await ensureRuntimeConfig();
  CONTROL_PLANE_URL = runtimeConfig.controlPlaneUrl;
  AGENT_AUTH_TOKEN = runtimeConfig.agentAuthToken;
  runtimeSensitiveValues.add(AGENT_AUTH_TOKEN);

  const lockAcquired = await acquireDaemonLock();
  if (!lockAcquired) {
    process.exitCode = 0;
    return;
  }

  opencodeOrchestrator = new OpenCodeOrchestrator(ALLOWED_PROJECT_ROOT_REAL, REQUEST_TIMEOUT_MS);
  log(`starting daemon root=${ALLOWED_PROJECT_ROOT_REAL} opencode=${OPENCODE_BASE_URL}`);
  
  // In UI-box mode, emit a ready event
  if (isUiBoxMode) {
    log("ui-box mode: emitting ready event");
  }
  
  connect();
}

// Main entry point
if (isSetupMode) {
  void handleCliSetup().catch((error) => {
    const message = error instanceof Error ? error.message : "setup_failed";
    console.error(`\n❌ Setup failed: ${message}`);
    process.exitCode = 1;
  });
} else {
  void startDaemon().catch((error) => {
    const message = error instanceof Error ? error.message : "startup_failed";
    log(`fatal startup error: ${message}`);
    process.exitCode = 1;
  });
}
