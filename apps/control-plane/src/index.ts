import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { config as loadDotenv } from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket, { WebSocketServer, type RawData } from "ws";
import {
  MAX_DIRECTORY_LIMIT,
  MAX_STREAM_CHUNK_BYTES,
  WS_PROTOCOL_VERSION,
  type ConfigCheckPushRequestMessage,
  type ConfigViewResponseMessage,
  type DirectoryResponseMessage,
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
  type SetupStatusRequestMessage,
  type SetupStatusResponseMessage,
  type SessionStatusRequestMessage,
  type SessionStatusResponseMessage,
  type SessionLogRequestMessage,
  type SessionJitCredential,
  type JitKillSwitchRequestMessage,
  type JitKillSwitchResponseMessage,
  type PortListMessage,
  type PortProxyRequestMessage,
  type PortProxyResponseMessage,
  type ProxyHeaderEntry,
  type SessionResultMessage,
  type StartPromptMessage,
  type StartSessionMessage,
  type StreamChunkMessage,
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
import {
  AGENT_TEMPLATE_SCHEMA,
  compileTemplateToSessionInitConfig,
  compileTemplateToRuntimeConfig,
  toCanonicalJson,
  validateAgentTemplate,
  validateMcpRegistryEntry,
  type AgentTemplate,
  type McpRegistryEntry,
} from "./config-registry.js";
import { AuthService, parseCookies, type AuthRole, type AuthSession } from "./auth.js";

const CONTROL_PLANE_ENV_FILE = process.env.CONTROL_PLANE_ENV_FILE?.trim();
if (CONTROL_PLANE_ENV_FILE) {
  loadDotenv({ path: CONTROL_PLANE_ENV_FILE });
} else {
  loadDotenv();
}

const CONTROL_PLANE_PORT = parseInt(process.env.CONTROL_PLANE_PORT ?? "8787", 10);
const CONTROL_PLANE_API_PORT = parseInt(process.env.CONTROL_PLANE_API_PORT ?? "8788", 10);
const REQUIRED_AGENT_PROTOCOL_VERSION_RAW = parseInt(process.env.REQUIRED_AGENT_PROTOCOL_VERSION ?? String(WS_PROTOCOL_VERSION), 10);
const REQUIRED_AGENT_PROTOCOL_VERSION = Number.isInteger(REQUIRED_AGENT_PROTOCOL_VERSION_RAW) && REQUIRED_AGENT_PROTOCOL_VERSION_RAW > 0
  ? REQUIRED_AGENT_PROTOCOL_VERSION_RAW
  : WS_PROTOCOL_VERSION;
const HEARTBEAT_SECONDS = parseInt(process.env.HEARTBEAT_SECONDS ?? "25", 10);
const HANDSHAKE_SKEW_MS = parseInt(process.env.HANDSHAKE_SKEW_MS ?? "30000", 10);
const MAX_FRAME_BYTES = parseInt(process.env.MAX_FRAME_BYTES ?? String(MAX_STREAM_CHUNK_BYTES + 1024), 10);
const MAX_NONCES = parseInt(process.env.MAX_NONCES ?? "2048", 10);
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS ?? "15000", 10);
const GIT_REQUEST_TIMEOUT_MS = parseInt(process.env.GIT_REQUEST_TIMEOUT_MS ?? "180000", 10);
const MAX_API_BODY_BYTES = parseInt(process.env.MAX_API_BODY_BYTES ?? "262144", 10);
const MAX_PROMPT_CHARS = parseInt(process.env.MAX_PROMPT_CHARS ?? "8000", 10);
const UI_MAX_PAYLOAD = parseInt(process.env.UI_MAX_PAYLOAD ?? "2048", 10);
const UI_MAX_BUFFER_BYTES = parseInt(process.env.UI_MAX_BUFFER_BYTES ?? "262144", 10);
const SESSION_LOG_REPLAY_LINES = parseInt(process.env.SESSION_LOG_REPLAY_LINES ?? "50", 10);
const SESSION_LOG_REPLAY_MAX_LINES = parseInt(process.env.SESSION_LOG_REPLAY_MAX_LINES ?? "200", 10);
const SESSION_SNAPSHOT_MIN_LINES = parseInt(process.env.SESSION_SNAPSHOT_MIN_LINES ?? "50", 10);
const SESSION_SNAPSHOT_MAX_LINES = parseInt(process.env.SESSION_SNAPSHOT_MAX_LINES ?? "100", 10);
const JIT_CREDENTIAL_DEFAULT_TTL_SECONDS = parseInt(process.env.JIT_CREDENTIAL_DEFAULT_TTL_SECONDS ?? "900", 10);
const JIT_CREDENTIAL_MIN_TTL_SECONDS = parseInt(process.env.JIT_CREDENTIAL_MIN_TTL_SECONDS ?? "30", 10);
const JIT_CREDENTIAL_MAX_TTL_SECONDS = parseInt(process.env.JIT_CREDENTIAL_MAX_TTL_SECONDS ?? "3600", 10);
const JIT_CREDENTIAL_DEFAULT_SCOPE = process.env.JIT_CREDENTIAL_DEFAULT_SCOPE ?? "opencode:session";
const JIT_CREDENTIAL_DEFAULT_ENV_VAR = process.env.JIT_CREDENTIAL_DEFAULT_ENV_VAR ?? "OPENCODE_SESSION_TOKEN";
const JIT_CREDENTIAL_ENV_MAX_PAIRS = parseInt(process.env.JIT_CREDENTIAL_ENV_MAX_PAIRS ?? "8", 10);
const JIT_CREDENTIAL_ENV_MAX_VALUE_BYTES = parseInt(process.env.JIT_CREDENTIAL_ENV_MAX_VALUE_BYTES ?? "2048", 10);
const JIT_CREDENTIAL_ENV_ALLOWLIST = parseJitEnvAllowlist(
  process.env.JIT_CREDENTIAL_ENV_ALLOWLIST
    ?? `${JIT_CREDENTIAL_DEFAULT_ENV_VAR},OPENCODE_JIT_SCOPE,OPENCODE_JIT_TOKEN_EXPIRES_AT`,
);
const JIT_CREDENTIAL_SIGNING_KEY = (process.env.JIT_CREDENTIAL_SIGNING_KEY ?? "").trim();
const PORT_PROXY_REQUEST_TIMEOUT_MS = parseInt(process.env.PORT_PROXY_REQUEST_TIMEOUT_MS ?? "20000", 10);
const PORT_PROXY_MAX_BODY_BYTES = parseInt(process.env.PORT_PROXY_MAX_BODY_BYTES ?? "1048576", 10);
const PORT_PROXY_MAX_HEADER_COUNT = parseInt(process.env.PORT_PROXY_MAX_HEADER_COUNT ?? "64", 10);
const MCP_GATEWAY_BASE_URLS = parseGatewayBaseUrls(process.env.MCP_GATEWAY_BASE_URLS ?? process.env.MCP_GATEWAY_BASE_URL ?? "");
const AUTH = AuthService.fromEnv(process.env);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_ROOT = path.resolve(__dirname, "../public");
const STATIC_ASSETS: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/index.html": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", type: "application/javascript; charset=utf-8" },
  "/styles.css": { file: "styles.css", type: "text/css; charset=utf-8" },
  "/login": { file: "login.html", type: "text/html; charset=utf-8" },
  "/login.html": { file: "login.html", type: "text/html; charset=utf-8" },
  "/login.js": { file: "login.js", type: "application/javascript; charset=utf-8" },
};

const validTokens = parseValidTokens(process.env.VALID_TOKENS ?? "");
const validTokenByKeyId = buildTokenKeyIdMap(validTokens);
const deviceRegistry = new Map<string, WebSocket>();
const deviceMeta = new Map<string, DeviceMeta>();
const socketState = new WeakMap<WebSocket, DeviceSocketState>();
const socketAlive = new WeakMap<WebSocket, boolean>();
const recentNonces = new Map<string, number>();
const pendingRequests = new Map<number, PendingRequest>();
const uiClients = new Set<WebSocket>();
const uiClientSubscriptions = new WeakMap<WebSocket, UiSubscription>();
const devicePortOwnership = new Map<string, PortOwnership>();
const sessionToDevice = new Map<string, string>();
const sessionToOwner = new Map<string, string>();
const pendingSnapshotPulls = new Map<string, PendingSnapshotPull>();
const mcpRegistry = new Map<string, McpRegistryEntry>();
const templateRegistry = new Map<string, AgentTemplate>();
const configPushState = new Map<string, ConfigPushStatus>();

let nextRequestId = 1;

const wss = new WebSocketServer({
  port: CONTROL_PLANE_PORT,
  clientTracking: false,
  perMessageDeflate: false,
  maxPayload: MAX_FRAME_BYTES,
});

const apiServer = createServer((request, response) => {
  void handleApiRequest(request, response);
});

const uiWss = new WebSocketServer({
  server: apiServer,
  path: "/ws-ui",
  clientTracking: false,
  perMessageDeflate: false,
  maxPayload: UI_MAX_PAYLOAD,
});

wss.on("listening", () => {
  log(`control-plane websocket listening on ws://0.0.0.0:${CONTROL_PLANE_PORT}`);
});

apiServer.listen(CONTROL_PLANE_API_PORT, () => {
  log(`control-plane api listening on http://0.0.0.0:${CONTROL_PLANE_API_PORT}`);
});

uiWss.on("connection", (ws, req) => {
  const session = getAuthenticatedSession(req);
  if (!session || !AUTH.roleAtLeast(session.role, "viewer")) {
    ws.close(4401, "unauthorized");
    return;
  }
  uiClients.add(ws);
  sendUiJson(ws, { t: "ready" });

  ws.on("message", (raw) => {
    const payload = decodeJson(raw);
    if (!isObject(payload)) {
      return;
    }
    if (payload.t === "sub" && matches(payload.d, /^[A-Za-z0-9_-]{12,32}$/) && matches(payload.x, /^[A-Za-z0-9_-]{8,24}$/)) {
      uiClientSubscriptions.set(ws, { deviceId: payload.d, streamId: payload.x });
      sendUiJson(ws, { t: "sub", o: 1, d: payload.d, x: payload.x });
      requestSessionLogReplay(payload.d, payload.x);
      return;
    }
    if (payload.t === "unsub") {
      uiClientSubscriptions.delete(ws);
      sendUiJson(ws, { t: "unsub", o: 1 });
    }
  });

  ws.on("close", () => {
    uiClients.delete(ws);
    uiClientSubscriptions.delete(ws);
  });

  ws.on("error", () => {
    uiClients.delete(ws);
    uiClientSubscriptions.delete(ws);
  });
});

wss.on("connection", (ws, req) => {
  socketAlive.set(ws, true);
  const remote = req.socket.remoteAddress ?? "unknown";
  log(`incoming websocket connection from ${remote}`);

  ws.on("pong", () => {
    socketAlive.set(ws, true);
  });

  ws.on("message", (raw) => {
    handleIncomingMessage(ws, raw);
  });

  ws.on("close", () => {
    unregisterSocket(ws);
    log(`socket closed (${remote})`);
  });

  ws.on("error", (error) => {
    log(`socket error (${remote}): ${error.message}`);
  });
});

const heartbeatTimer = setInterval(() => {
  pruneNonceCache();
  for (const [deviceId, ws] of deviceRegistry.entries()) {
    if (ws.readyState !== WebSocket.OPEN) {
      deviceRegistry.delete(deviceId);
      continue;
    }
    if (!socketAlive.get(ws)) {
      log(`dropping stale socket for device ${deviceId}`);
      ws.terminate();
      deviceRegistry.delete(deviceId);
      rejectPendingForDevice(deviceId, "device disconnected");
      continue;
    }
    socketAlive.set(ws, false);
    ws.ping();
  }
}, Math.max(5, HEARTBEAT_SECONDS) * 1000);

heartbeatTimer.unref();

function handleIncomingMessage(ws: WebSocket, raw: RawData): void {
  const payload = decodeJson(raw);
  if (payload === null) {
    sendError(ws, "PROTO");
    ws.close(1002, "invalid json");
    return;
  }

  const state = socketState.get(ws);
  if (!state) {
    const handshakeVersion = parseHandshakeProtocolVersion(payload);
    if (handshakeVersion !== null) {
      if (handshakeVersion < REQUIRED_AGENT_PROTOCOL_VERSION) {
        sendError(ws, "UPDATE_REQUIRED", undefined, `agent_update_required:min_v${REQUIRED_AGENT_PROTOCOL_VERSION}:received_v${handshakeVersion}`);
        ws.close(1008, "update required");
        return;
      }
      if (handshakeVersion !== WS_PROTOCOL_VERSION) {
        sendError(ws, "UPDATE_REQUIRED", undefined, `protocol_not_supported:control_plane_v${WS_PROTOCOL_VERSION}:received_v${handshakeVersion}`);
        ws.close(1002, "unsupported protocol version");
        return;
      }
    }

    const h1 = parseHandshakeInit(payload);
    if (!h1) {
      sendError(ws, "PROTO");
      ws.close(1002, "expected handshake");
      return;
    }
    completeHandshake(ws, h1);
    return;
  }

  const telemetry = parseTelemetryPing(payload);
  if (telemetry) {
    const meta = deviceMeta.get(state.deviceId);
    if (meta) {
      meta.lastSeenAt = Date.now();
      meta.rss = telemetry.r;
      meta.uptime = telemetry.u;
    }
    return;
  }

  const portList = parsePortList(payload);
  if (portList) {
    const meta = deviceMeta.get(state.deviceId);
    if (meta) {
      meta.lastSeenAt = Date.now();
      meta.exposedPorts = portList.p;
      meta.exposedPortsUpdatedAt = Date.now();
    }
    return;
  }

  const directoryResponse = parseDirectoryResponse(payload);
  if (directoryResponse) {
    settlePending(directoryResponse.i, state.deviceId, "ds", directoryResponse);
    return;
  }

  const sessionResult = parseSessionResult(payload);
  if (sessionResult) {
    settlePending(sessionResult.i, state.deviceId, "sr", sessionResult);
    return;
  }

  const sessionStatus = parseSessionStatusResponse(payload);
  if (sessionStatus) {
    settlePending(sessionStatus.i, state.deviceId, "sv", sessionStatus);
    return;
  }

  const setupStatus = parseSetupStatusResponse(payload);
  if (setupStatus) {
    settlePending(setupStatus.i, state.deviceId, "cg", setupStatus);
    return;
  }

  const setupSave = parseSetupSaveResponse(payload);
  if (setupSave) {
    settlePending(setupSave.i, state.deviceId, "cv", setupSave);
    return;
  }

  const configView = parseConfigViewResponse(payload);
  if (configView) {
    configPushState.set(`${state.deviceId}:${configView.i}`, {
      deviceId: state.deviceId,
      requestId: configView.i,
      templateId: configView.tid,
      templateVersion: configView.tv,
      status: configView.st,
      digest: configView.pd,
      ...(configView.ph ? { phase: configView.ph } : {}),
      ...(configView.sc ? { scope: configView.sc } : {}),
      ...(configView.pm ? { policyMode: configView.pm } : {}),
      ...(configView.ap ? { appliedPath: configView.ap } : {}),
      ...(configView.vd ? { violations: configView.vd } : {}),
      ...(configView.m ? { message: configView.m } : {}),
      respondedAt: configView.at,
    });
    settlePending(configView.i, state.deviceId, "cvcfg", configView);
    return;
  }

  const killSwitchResponse = parseJitKillSwitchResponse(payload);
  if (killSwitchResponse) {
    settlePending(killSwitchResponse.i, state.deviceId, "jv", killSwitchResponse);
    return;
  }

  const mkdirResponse = parseMkdirResponse(payload);
  if (mkdirResponse) {
    settlePending(mkdirResponse.i, state.deviceId, "mr", mkdirResponse);
    return;
  }

  const rmdirResponse = parseRmdirResponse(payload);
  if (rmdirResponse) {
    settlePending(rmdirResponse.i, state.deviceId, "rr", rmdirResponse);
    return;
  }

  const renameResponse = parseRenameResponse(payload);
  if (renameResponse) {
    settlePending(renameResponse.i, state.deviceId, "rp", renameResponse);
    return;
  }

  // Git Response Handlers
  const gitStatusResponse = parseGitStatusResponse(payload);
  if (gitStatusResponse) {
    settlePending(gitStatusResponse.i, state.deviceId, "gt", gitStatusResponse);
    return;
  }

  const gitInitResponse = parseGitInitResponse(payload);
  if (gitInitResponse) {
    settlePending(gitInitResponse.i, state.deviceId, "gj", gitInitResponse);
    return;
  }

  const gitCloneResponse = parseGitCloneResponse(payload);
  if (gitCloneResponse) {
    settlePending(gitCloneResponse.i, state.deviceId, "gl", gitCloneResponse);
    return;
  }

  const gitAddResponse = parseGitAddResponse(payload);
  if (gitAddResponse) {
    settlePending(gitAddResponse.i, state.deviceId, "gb", gitAddResponse);
    return;
  }

  const gitCommitResponse = parseGitCommitResponse(payload);
  if (gitCommitResponse) {
    settlePending(gitCommitResponse.i, state.deviceId, "go", gitCommitResponse);
    return;
  }

  const gitPushResponse = parseGitPushResponse(payload);
  if (gitPushResponse) {
    settlePending(gitPushResponse.i, state.deviceId, "gd", gitPushResponse);
    return;
  }

  const gitPullResponse = parseGitPullResponse(payload);
  if (gitPullResponse) {
    settlePending(gitPullResponse.i, state.deviceId, "gn", gitPullResponse);
    return;
  }

  const gitBranchResponse = parseGitBranchResponse(payload);
  if (gitBranchResponse) {
    settlePending(gitBranchResponse.i, state.deviceId, "gu", gitBranchResponse);
    return;
  }

  const gitCheckoutResponse = parseGitCheckoutResponse(payload);
  if (gitCheckoutResponse) {
    settlePending(gitCheckoutResponse.i, state.deviceId, "gy", gitCheckoutResponse);
    return;
  }

  const gitConfigResponse = parseGitConfigResponse(payload);
  if (gitConfigResponse) {
    settlePending(gitConfigResponse.i, state.deviceId, "gv", gitConfigResponse);
    return;
  }

  const gitLogMessage = parseGitLogMessage(payload);
  if (gitLogMessage) {
    routeUiGitLog(state.deviceId, gitLogMessage);
    return;
  }

  const streamChunk = parseStreamChunk(payload);
  if (streamChunk) {
    if (consumeSnapshotChunk(state.deviceId, streamChunk)) {
      sendJson(ws, { v: WS_PROTOCOL_VERSION, t: "sa", x: streamChunk.x, q: streamChunk.q });
      return;
    }
    routeStreamChunk(state.deviceId, streamChunk);
    sendJson(ws, { v: WS_PROTOCOL_VERSION, t: "sa", x: streamChunk.x, q: streamChunk.q });
    return;
  }

  const proxyResponse = parsePortProxyResponse(payload);
  if (proxyResponse) {
    settlePending(proxyResponse.i, state.deviceId, "pv", proxyResponse);
    return;
  }

  const errorMessage = parseErrorMessage(payload);
  if (errorMessage) {
    if (errorMessage.i !== undefined) {
      const wasPending = failPending(errorMessage.i, state.deviceId, `remote error: ${errorMessage.c}`);
      if (!wasPending) {
        routeUiError(state.deviceId, errorMessage.i, errorMessage.c);
      }
    } else {
      routeUiError(state.deviceId, undefined, errorMessage.c);
    }
    return;
  }

  sendError(ws, "PROTO");
}

function completeHandshake(ws: WebSocket, message: HandshakeInitMessage): void {
  const now = Date.now();
  if (Math.abs(now - message.ts) > HANDSHAKE_SKEW_MS) {
    sendError(ws, "AUTH");
    ws.close(1008, "timestamp skew");
    return;
  }

  const nonceExpiry = recentNonces.get(message.n);
  if (nonceExpiry && nonceExpiry > now) {
    sendError(ws, "AUTH");
    ws.close(1008, "replay detected");
    return;
  }

  const token = resolveHandshakeToken(message);
  if (!token) {
    sendError(ws, "AUTH");
    ws.close(1008, "invalid token");
    return;
  }

  const expectedMac = sign(token, canonicalH1(message));
  const legacyExpectedMac = message.at ? sign(token, canonicalH1Legacy(message)) : undefined;
  const validMac = secureEqual(message.m, expectedMac) || (legacyExpectedMac ? secureEqual(message.m, legacyExpectedMac) : false);
  if (!validMac) {
    sendError(ws, "AUTH");
    ws.close(1008, "invalid signature");
    return;
  }

  recentNonces.set(message.n, now + HANDSHAKE_SKEW_MS);
  if (recentNonces.size > MAX_NONCES) {
    pruneNonceCache();
  }

  const previous = deviceRegistry.get(message.d);
  if (previous && previous !== ws) {
    log(`replacing active connection for device ${message.d}`);
    previous.close(1012, "replaced");
  }

  const sid = randomToken(18);
  const serverNonce = randomToken(18);
  const hb = Math.max(5, HEARTBEAT_SECONDS);

  const ack: HandshakeAckMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "h2",
    s: sid,
    n: serverNonce,
    hb,
    mx: MAX_STREAM_CHUNK_BYTES,
    m: sign(token, canonicalH2(sid, serverNonce, hb, MAX_STREAM_CHUNK_BYTES, message.n)),
  };

  deviceRegistry.set(message.d, ws);
  deviceMeta.set(message.d, {
    sid,
    connectedAt: now,
    lastSeenAt: now,
    ...(message.hn ? { hostname: message.hn } : {}),
    ...(message.os ? { os: message.os } : {}),
    ...(message.av ? { agentVersion: message.av } : {}),
    rss: 0,
    uptime: 0,
    exposedPorts: [],
    exposedPortsUpdatedAt: now,
  });
  socketState.set(ws, { deviceId: message.d, sid });

  sendJson(ws, ack);
  log(`device registered: ${message.d} sid=${sid}`);
}

function unregisterSocket(ws: WebSocket): void {
  const state = socketState.get(ws);
  if (!state) {
    return;
  }
  const current = deviceRegistry.get(state.deviceId);
  if (current === ws) {
    deviceRegistry.delete(state.deviceId);
    deviceMeta.delete(state.deviceId);
    devicePortOwnership.delete(state.deviceId);
    for (const [sessionId, mappedDeviceId] of sessionToDevice.entries()) {
      if (mappedDeviceId === state.deviceId) {
        sessionToDevice.delete(sessionId);
        sessionToOwner.delete(sessionId);
      }
    }
    for (const [key, pending] of pendingSnapshotPulls.entries()) {
      if (pending.deviceId !== state.deviceId) {
        continue;
      }
      clearTimeout(pending.timer);
      pendingSnapshotPulls.delete(key);
      pending.reject(new ApiError(502, "device disconnected"));
    }
    rejectPendingForDevice(state.deviceId, "device disconnected");
    log(`device unregistered: ${state.deviceId} sid=${state.sid}`);
  }
  socketState.delete(ws);
  socketAlive.delete(ws);
}

async function handleApiRequest(request: IncomingMessage, response: ServerResponse): Promise<void> {
  try {
    const method = request.method ?? "GET";
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    const pathname = url.pathname;
    applySecurityHeaders(response);
    const cookies = parseCookies(request.headers.cookie);

    if (method === "GET" && pathname === "/health") {
      sendJsonResponse(response, 200, { ok: true });
      return;
    }

    if (pathname === "/auth/login" && method === "POST") {
      await handleLogin(request, response, cookies);
      return;
    }
    if (pathname === "/auth/logout" && method === "POST") {
      await handleLogout(request, response, cookies);
      return;
    }
    if (pathname === "/auth/session" && method === "GET") {
      const session = AUTH.getSession(cookies);
      if (!session) {
        sendJsonResponse(response, 401, { error: "auth_required" });
        return;
      }
      sendJsonResponse(response, 200, { o: 1, user: { email: session.email, role: session.role } });
      return;
    }

    const auth = AUTH.getSession(cookies);
    if (method === "GET") {
      const staticAsset = STATIC_ASSETS[pathname];
      if (staticAsset) {
        if (pathname === "/login" || pathname === "/login.html" || pathname === "/login.js" || pathname === "/styles.css") {
          await sendStaticAsset(response, staticAsset.file, staticAsset.type);
          return;
        }
        if (!auth) {
          sendLoginRedirect(response);
          return;
        }
        await sendStaticAsset(response, staticAsset.file, staticAsset.type);
        return;
      }
    }

    if (!auth) {
      sendJsonResponse(response, 401, { error: "auth_required" });
      return;
    }
    if (!isAuthorizedRoute(method, pathname, auth.role)) {
      sendJsonResponse(response, 403, { error: "forbidden" });
      return;
    }
    if (requiresCsrf(method, pathname)) {
      const csrfHeader = readCsrfHeader(request.headers["x-csrf-token"]);
      const csrfCookie = cookies[AUTH.config.csrfCookieName];
      if (!AUTH.isCsrfValid(auth, csrfHeader, csrfCookie)) {
        sendJsonResponse(response, 403, { error: "csrf_invalid" });
        return;
      }
    }

    if (method === "GET" && pathname === "/devices") {
      const devices = Array.from(deviceRegistry.keys(), (deviceId) => {
        const meta = deviceMeta.get(deviceId);
        return {
          d: deviceId,
          s: meta?.sid ?? "",
          hn: meta?.hostname,
          os: meta?.os,
          av: meta?.agentVersion,
          u: meta?.uptime ?? 0,
          r: meta?.rss ?? 0,
          ls: meta?.lastSeenAt ?? 0,
          pt: meta?.exposedPorts ?? [],
        };
      });
      sendJsonResponse(response, 200, { v: WS_PROTOCOL_VERSION, devices });
      return;
    }

    if (method === "GET" && pathname === "/config/template/schema") {
      sendJsonResponse(response, 200, { schema: AGENT_TEMPLATE_SCHEMA });
      return;
    }

    if (method === "GET" && pathname === "/config/mcp") {
      sendJsonResponse(response, 200, {
        entries: Array.from(mcpRegistry.values()).sort((left, right) => {
          const keyLeft = `${left.serverId}@${left.version}`;
          const keyRight = `${right.serverId}@${right.version}`;
          return keyLeft.localeCompare(keyRight);
        }),
      });
      return;
    }

    if (method === "GET" && pathname === "/config/templates") {
      sendJsonResponse(response, 200, {
        templates: Array.from(templateRegistry.values()).sort((left, right) => {
          const keyLeft = `${left.templateId}@${left.templateVersion}`;
          const keyRight = `${right.templateId}@${right.templateVersion}`;
          return keyLeft.localeCompare(keyRight);
        }),
      });
      return;
    }

    const configStatusMatch = /^\/devices\/([^/]+)\/config\/status\/(\d+)$/.exec(pathname);
    if (method === "GET" && configStatusMatch) {
      const deviceId = decodeURIComponent(configStatusMatch[1]!);
      const requestId = parseInt(configStatusMatch[2]!, 10);
      if (!Number.isInteger(requestId) || requestId < 1 || requestId > 0xffffffff) {
        throw new ApiError(400, "invalid_request_id");
      }
      const state = configPushState.get(`${deviceId}:${requestId}`);
      if (!state) {
        throw new ApiError(404, "config_status_not_found");
      }
      sendJsonResponse(response, 200, state);
      return;
    }

    const snapshotMatch = /^\/session\/([^/]+)\/snapshot$/.exec(pathname);
    if (method === "GET" && snapshotMatch) {
      const sessionId = readSessionId(decodeURIComponent(snapshotMatch[1]!));
      const mappedDeviceId = sessionToDevice.get(sessionId);
      const mappedOwner = sessionToOwner.get(sessionId);
      if (!mappedDeviceId || !mappedOwner) {
        throw new ApiError(404, "snapshot_not_found");
      }
      if (mappedOwner !== auth.subject) {
        throw new ApiError(403, "snapshot_access_denied");
      }

      const tail = clampInt(
        parseInt(url.searchParams.get("tail") ?? String(SESSION_SNAPSHOT_MAX_LINES), 10),
        SESSION_SNAPSHOT_MIN_LINES,
        SESSION_SNAPSHOT_MAX_LINES,
        SESSION_SNAPSHOT_MAX_LINES,
      );
      const rawSnapshot = await requestSnapshotTailFromAgent(mappedDeviceId, tail);
      const entries = parseSnapshotJsonLines(rawSnapshot);
      sendJsonResponse(response, 200, {
        o: 1,
        s: sessionId,
        d: mappedDeviceId,
        e: entries,
      });
      return;
    }

    const proxyMatch = /^\/device\/([^/]+)\/port\/(\d{1,5})(\/.*)?$/.exec(pathname);
    if (proxyMatch) {
      const deviceId = decodeURIComponent(proxyMatch[1]!);
      const port = parseInt(proxyMatch[2]!, 10);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new ApiError(400, "invalid_port");
      }

      const ownership = devicePortOwnership.get(deviceId);
      if (!ownership || ownership.principalId !== auth.subject) {
        throw new ApiError(403, "port_access_denied");
      }

      const pathSuffix = proxyMatch[3] ?? "/";
      const proxyPath = `${pathSuffix}${url.search}`;
      const rawBody = await readRawBody(request, PORT_PROXY_MAX_BODY_BYTES);
      const proxied = await proxyHttpToDevice(deviceId, port, method, proxyPath, request.headers, rawBody);
      sendProxyResponse(response, proxied.status, proxied.statusText, proxied.headers, proxied.body);
      return;
    }

    if (method === "POST") {
      const body = await readJsonBody(request, MAX_API_BODY_BYTES);

      if (pathname === "/config/mcp") {
        const validated = validateMcpRegistryEntry(body.entry);
        if (!validated.ok) {
          throw new ApiError(400, validated.errors.join(","));
        }
        const key = buildMcpRegistryKey(validated.entry.serverId, validated.entry.version);
        mcpRegistry.set(key, validated.entry);
        sendJsonResponse(response, 200, { o: 1, key });
        return;
      }

      if (pathname === "/config/templates") {
        const validated = validateAgentTemplate(body.template);
        if (!validated.ok) {
          throw new ApiError(400, validated.errors.join(","));
        }
        const key = buildTemplateKey(validated.template.templateId, validated.template.templateVersion);
        templateRegistry.set(key, validated.template);
        sendJsonResponse(response, 200, { o: 1, key });
        return;
      }

      const compileMatch = /^\/config\/templates\/([^/]+)\/compile$/.exec(pathname);
      if (compileMatch) {
        const templateId = decodeURIComponent(compileMatch[1]!);
        const templateVersion = readString(body.templateVersion, "");
        const template = getTemplateForCompile(templateId, templateVersion);
        const compiled = compileTemplateToRuntimeConfig(
          template,
          (serverId, version) => mcpRegistry.get(buildMcpRegistryKey(serverId, version)),
          { resolveGatewayUrl: resolveGatewayMcpUrl },
        );
        if (!compiled.ok) {
          throw new ApiError(400, compiled.errors.join(","));
        }
        sendJsonResponse(response, 200, {
          o: 1,
          templateId: template.templateId,
          templateVersion: template.templateVersion,
          digest: compiled.digest,
          config: compiled.compiledConfig,
        });
        return;
      }

      const directoryMatch = /^\/devices\/([^/]+)\/dir$/.exec(pathname);
      if (directoryMatch) {
        const deviceId = decodeURIComponent(directoryMatch[1]!);
        const requestPath = readString(body.path, "");
        const rootAlias = readString(body.root, "cwd");
        const cursor = typeof body.cursor === "string" ? body.cursor : undefined;
        const limit = clampInt(body.limit, 1, MAX_DIRECTORY_LIMIT, 128);
        try {
          const result = await requestDirectory(deviceId, rootAlias, requestPath, limit, cursor);
          sendJsonResponse(response, 200, result);
        } catch (error) {
          sendDirectoryError(response, error);
        }
        return;
      }

      const startMatch = /^\/devices\/([^/]+)\/session\/start$/.exec(pathname);
      if (startMatch) {
        const deviceId = decodeURIComponent(startMatch[1]!);
        const sessionId = body.sessionId === undefined ? randomToken(18) : readSessionId(body.sessionId);
        const folderPath = readString(body.path, ".");
        const jitCredential = buildSessionJitCredential(body, deviceId, sessionId);

        const assignedTemplateId = readString(body.templateId, "").trim();
        const assignedTemplateVersion = readString(body.templateVersion, "").trim();
        if (assignedTemplateVersion && !assignedTemplateId) {
          throw new ApiError(400, "template_id_required_for_template_version");
        }
        if (assignedTemplateId) {
          const template = getTemplateForCompile(assignedTemplateId, assignedTemplateVersion);
          const compileInit = compileTemplateToSessionInitConfig(
            template,
            (serverId, version) => mcpRegistry.get(buildMcpRegistryKey(serverId, version)),
          );
          if (!compileInit.ok) {
            throw new ApiError(400, compileInit.errors.join(","));
          }
          const injection = await pushCompiledConfig(deviceId, {
            template,
            applyPath: readString(body.applyPath, ".opencode/opencode.json").trim(),
            digest: compileInit.digest,
            config: compileInit.compiledConfig,
            policyMode: template.policy.mode,
            signatureAlgorithm: "",
            signature: "",
            phase: "session-init",
            scope: "session-init",
          });
          if (injection.o !== 1 || injection.st !== "applied") {
            throw new ApiError(
              400,
              `template_injection_failed:${(injection.vd ?? []).join("|") || injection.m || "config_rejected"}`,
            );
          }
        }

        const result = await startSession(deviceId, sessionId, folderPath, jitCredential);
        if (result.o === 1) {
          const effectiveSessionId = typeof result.s === "string" ? result.s : sessionId;
          sessionToDevice.set(effectiveSessionId, deviceId);
          sessionToOwner.set(effectiveSessionId, auth.subject);
          devicePortOwnership.set(deviceId, {
            principalId: auth.subject,
            sessionId: effectiveSessionId,
            assignedAt: Date.now(),
          });
        }
        sendJsonResponse(response, 200, result);
        return;
      }

      const terminateMatch = /^\/devices\/([^/]+)\/session\/terminate$/.exec(pathname);
      if (terminateMatch) {
        const deviceId = decodeURIComponent(terminateMatch[1]!);
        const requestedSessionId = body.sessionId === undefined ? "" : readSessionId(body.sessionId);
        const ownedSessionId = devicePortOwnership.get(deviceId)?.sessionId;
        const sessionId = requestedSessionId || ownedSessionId;
        if (!sessionId) {
          throw new ApiError(400, "invalid_session_id");
        }
        const result = await terminateSession(deviceId, sessionId);
        if (result.o === 1) {
          sessionToDevice.delete(sessionId);
          sessionToOwner.delete(sessionId);
          const ownership = devicePortOwnership.get(deviceId);
          if (ownership && ownership.sessionId === sessionId) {
            devicePortOwnership.delete(deviceId);
          }
        }
        sendJsonResponse(response, 200, result);
        return;
      }

      const killSwitchMatch = /^\/devices\/([^/]+)\/jit\/kill$/.exec(pathname);
      if (killSwitchMatch) {
        const deviceId = decodeURIComponent(killSwitchMatch[1]!);
        const sessionId = typeof body.sessionId === "string" && body.sessionId.trim()
          ? readSessionId(body.sessionId)
          : undefined;
        const credentialRef = readString(body.credentialRef, readString(body.jitRef, "")).trim() || undefined;
        if (credentialRef && !/^[A-Za-z0-9._:-]{1,128}$/.test(credentialRef)) {
          throw new ApiError(400, "invalid_jit_ref");
        }
        const reason = readString(body.reason, "abnormal_behavior").trim() || "abnormal_behavior";
        if (reason.length > 128) {
          throw new ApiError(400, "invalid_reason");
        }
        const closeTunnel = body.closeTunnel === 1 || body.closeTunnel === true ? 1 : 0;
        const result = await triggerJitKillSwitch(deviceId, sessionId, credentialRef, reason, closeTunnel);
        auditLog("jit.kill_switch", {
          actor: auth.email,
          role: auth.role,
          deviceId,
          sessionId,
          credentialRef,
          outcome: result.o,
          reason,
        });
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const statusMatch = /^\/devices\/([^/]+)\/session\/status$/.exec(pathname);
      if (statusMatch) {
        const deviceId = decodeURIComponent(statusMatch[1]!);
        const folderPath = readString(body.path, ".");
        const result = await getSessionStatus(deviceId, folderPath);
        sendJsonResponse(response, 200, result);
        return;
      }

      const setupStatusMatch = /^\/devices\/([^/]+)\/setup\/status$/.exec(pathname);
      if (setupStatusMatch) {
        const deviceId = decodeURIComponent(setupStatusMatch[1]!);
        const result = await getSetupStatus(deviceId);
        sendJsonResponse(response, 200, result);
        return;
      }

      const setupSaveMatch = /^\/devices\/([^/]+)\/setup\/save$/.exec(pathname);
      if (setupSaveMatch) {
        const deviceId = decodeURIComponent(setupSaveMatch[1]!);
        const suppliedAgentAuthToken = readString(body.agentAuthToken, "").trim();
        if (suppliedAgentAuthToken) {
          throw new ApiError(400, "agent_auth_token_must_be_set_locally");
        }
        const request = {
          controlPlaneUrl: readString(body.controlPlaneUrl, ""),
          agentAuthToken: "",
          opencodeCommand: readString(body.opencodeCommand, ""),
          opencodeHost: readString(body.opencodeHost, ""),
          opencodeStartPort: clampInt(body.opencodeStartPort, 1, 65535, 4096),
          opencodeProviderId: readString(body.opencodeProviderId, ""),
          opencodeModelId: readString(body.opencodeModelId, ""),
          requestTimeoutMs: clampInt(body.requestTimeoutMs, 1000, 120000, 10000),
        };
        const result = await saveSetupConfig(deviceId, request);
        auditLog("setup.save", {
          actor: auth.email,
          role: auth.role,
          deviceId,
          outcome: result.o,
        });
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const configPushMatch = /^\/devices\/([^/]+)\/config\/push$/.exec(pathname);
      if (configPushMatch) {
        const deviceId = decodeURIComponent(configPushMatch[1]!);
        const templateId = readString(body.templateId, "").trim();
        const templateVersion = readString(body.templateVersion, "").trim();
        const applyPath = readString(body.applyPath, ".opencode/opencode.json").trim();
        const signatureAlgorithm = readString(body.signatureAlgorithm, "").trim();
        const signature = readString(body.signature, "").trim();
        if (!templateId) {
          throw new ApiError(400, "invalid_template_id");
        }
        const template = getTemplateForCompile(templateId, templateVersion);
        const compiled = compileTemplateToRuntimeConfig(
          template,
          (serverId, version) => mcpRegistry.get(buildMcpRegistryKey(serverId, version)),
          { resolveGatewayUrl: resolveGatewayMcpUrl },
        );
        if (!compiled.ok) {
          throw new ApiError(400, compiled.errors.join(","));
        }

        const result = await pushCompiledConfig(deviceId, {
          template,
          applyPath,
          digest: compiled.digest,
          config: compiled.compiledConfig,
          policyMode: template.policy.mode,
          signatureAlgorithm,
          signature,
          phase: "runtime",
          scope: "full",
        });
        auditLog("config.push", {
          actor: auth.email,
          role: auth.role,
          deviceId,
          templateId,
          templateVersion: template.templateVersion,
          digest: compiled.digest,
          outcome: result.o,
          status: result.st,
        });
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const promptMatch = /^\/devices\/([^/]+)\/prompt$/.exec(pathname);
      if (promptMatch) {
        const deviceId = decodeURIComponent(promptMatch[1]!);
        const sessionId = readSessionId(body.sessionId);
        const prompt = readPrompt(body.prompt);
        const streamId = readStreamId(body.streamId) ?? randomToken(16);
        const result = startPrompt(deviceId, sessionId, streamId, prompt);
        sendJsonResponse(response, 202, result);
        return;
      }

      // Folder operations
      const mkdirMatch = /^\/devices\/([^/]+)\/mkdir$/.exec(pathname);
      if (mkdirMatch) {
        const deviceId = decodeURIComponent(mkdirMatch[1]!);
        const requestPath = readString(body.path, "");
        const rootAlias = readString(body.root, "cwd");
        const result = await mkdir(deviceId, rootAlias, requestPath);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const rmdirMatch = /^\/devices\/([^/]+)\/rmdir$/.exec(pathname);
      if (rmdirMatch) {
        const deviceId = decodeURIComponent(rmdirMatch[1]!);
        const requestPath = readString(body.path, "");
        const rootAlias = readString(body.root, "cwd");
        const result = await rmdir(deviceId, rootAlias, requestPath);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const renameMatch = /^\/devices\/([^/]+)\/rename$/.exec(pathname);
      if (renameMatch) {
        const deviceId = decodeURIComponent(renameMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const sourcePath = readString(body.source, "");
        const destPath = readString(body.dest, "");
        const result = await rename(deviceId, rootAlias, sourcePath, destPath);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      // Git operations
      const gitStatusMatch = /^\/devices\/([^/]+)\/git\/status$/.exec(pathname);
      if (gitStatusMatch) {
        const deviceId = decodeURIComponent(gitStatusMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const result = await gitStatus(deviceId, rootAlias, requestPath);
        sendJsonResponse(response, 200, result);
        return;
      }

      const gitInitMatch = /^\/devices\/([^/]+)\/git\/init$/.exec(pathname);
      if (gitInitMatch) {
        const deviceId = decodeURIComponent(gitInitMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const result = await gitInit(deviceId, rootAlias, requestPath);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const gitCloneMatch = /^\/devices\/([^/]+)\/git\/clone$/.exec(pathname);
      if (gitCloneMatch) {
        const deviceId = decodeURIComponent(gitCloneMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const repoUrl = readString(body.url, "");
        const branch = readString(body.branch, "");
        const result = await gitClone(deviceId, rootAlias, requestPath, repoUrl, branch);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const gitAddMatch = /^\/devices\/([^/]+)\/git\/add$/.exec(pathname);
      if (gitAddMatch) {
        const deviceId = decodeURIComponent(gitAddMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const files = readString(body.files, "");
        const all = body.all === 1 || body.all === true ? 1 : 0;
        const result = await gitAdd(deviceId, rootAlias, requestPath, files, all);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const gitCommitMatch = /^\/devices\/([^/]+)\/git\/commit$/.exec(pathname);
      if (gitCommitMatch) {
        const deviceId = decodeURIComponent(gitCommitMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const message = readString(body.message, "");
        const amend = body.amend === 1 || body.amend === true ? 1 : 0;
        const result = await gitCommit(deviceId, rootAlias, requestPath, message, amend);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const gitPushMatch = /^\/devices\/([^/]+)\/git\/push$/.exec(pathname);
      if (gitPushMatch) {
        const deviceId = decodeURIComponent(gitPushMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const remote = readString(body.remote, "origin");
        const branch = readString(body.branch, "");
        const result = await gitPush(deviceId, rootAlias, requestPath, remote, branch);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const gitPullMatch = /^\/devices\/([^/]+)\/git\/pull$/.exec(pathname);
      if (gitPullMatch) {
        const deviceId = decodeURIComponent(gitPullMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const remote = readString(body.remote, "origin");
        const branch = readString(body.branch, "");
        const result = await gitPull(deviceId, rootAlias, requestPath, remote, branch);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const gitBranchMatch = /^\/devices\/([^/]+)\/git\/branch$/.exec(pathname);
      if (gitBranchMatch) {
        const deviceId = decodeURIComponent(gitBranchMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const action = readString(body.action, "list") as "list" | "create" | "delete";
        const branchName = readString(body.branch, "");
        const result = await gitBranch(deviceId, rootAlias, requestPath, action, branchName);
        sendJsonResponse(response, 200, result);
        return;
      }

      const gitCheckoutMatch = /^\/devices\/([^/]+)\/git\/checkout$/.exec(pathname);
      if (gitCheckoutMatch) {
        const deviceId = decodeURIComponent(gitCheckoutMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const branch = readString(body.branch, "");
        const create = body.create === 1 || body.create === true ? 1 : 0;
        const result = await gitCheckout(deviceId, rootAlias, requestPath, branch, create);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }

      const gitConfigMatch = /^\/devices\/([^/]+)\/git\/config$/.exec(pathname);
      if (gitConfigMatch) {
        const deviceId = decodeURIComponent(gitConfigMatch[1]!);
        const rootAlias = readString(body.root, "cwd");
        const requestPath = readString(body.path, ".");
        const action = readString(body.action, "get") as "get" | "set";
        const name = readString(body.name, "");
        const email = readString(body.email, "");
        const global = body.global === 1 || body.global === true ? 1 : 0;
        const credentialManager = body.credentialManager === 1 || body.credentialManager === true ? 1 : 0;
        const result = await gitConfig(deviceId, rootAlias, requestPath, action, name, email, global, credentialManager);
        sendJsonResponse(response, result.o === 1 ? 200 : 400, result);
        return;
      }
    }

    sendJsonResponse(response, 404, { error: "not_found" });
  } catch (error) {
    if (error instanceof ApiError) {
      sendJsonResponse(response, error.statusCode, { error: error.message });
      return;
    }
    const message = error instanceof Error ? error.message : "internal_error";
    sendJsonResponse(response, 500, { error: message });
  }
}

function getAuthenticatedSession(request: IncomingMessage): AuthSession | null {
  const cookies = parseCookies(request.headers.cookie);
  return AUTH.getSession(cookies);
}

async function handleLogin(request: IncomingMessage, response: ServerResponse, _cookies: Record<string, string>): Promise<void> {
  const body = await readJsonBody(request, MAX_API_BODY_BYTES);
  const email = readString(body.email, "").trim().toLowerCase();
  const password = readString(body.password, "");
  const totpCode = readString(body.totpCode, "").replace(/\s+/g, "");
  const ipAddress = getClientIp(request);
  const result = AUTH.login(email, password, totpCode, ipAddress);
  if (!result.ok) {
    auditLog("auth.login.failed", {
      email,
      ipAddress,
      reason: result.error,
    });
    const status = result.error === "rate_limited"
      ? 429
      : result.error === "mfa_not_configured"
        ? 412
        : 401;
    sendJsonResponse(response, status, { error: result.error });
    return;
  }
  response.setHeader("set-cookie", AUTH.buildSetSessionCookies(result.session));
  auditLog("auth.login.success", {
    email: result.session.email,
    role: result.session.role,
    ipAddress,
  });
  sendJsonResponse(response, 200, {
    o: 1,
    user: { email: result.session.email, role: result.session.role },
  });
}

async function handleLogout(request: IncomingMessage, response: ServerResponse, cookies: Record<string, string>): Promise<void> {
  const session = AUTH.getSession(cookies);
  if (!session) {
    sendJsonResponse(response, 200, { o: 1 });
    return;
  }
  if (requiresCsrf(request.method ?? "POST", "/auth/logout")) {
    const csrfHeader = readCsrfHeader(request.headers["x-csrf-token"]);
    const csrfCookie = cookies[AUTH.config.csrfCookieName];
    if (!AUTH.isCsrfValid(session, csrfHeader, csrfCookie)) {
      sendJsonResponse(response, 403, { error: "csrf_invalid" });
      return;
    }
  }
  AUTH.logout(cookies);
  response.setHeader("set-cookie", AUTH.buildClearSessionCookies());
  auditLog("auth.logout", { email: session.email, role: session.role, ipAddress: getClientIp(request) });
  sendJsonResponse(response, 200, { o: 1 });
}

function readCsrfHeader(value: string | string[] | undefined): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value) && value.length > 0 && typeof value[0] === "string") {
    return value[0];
  }
  return undefined;
}

function sendLoginRedirect(response: ServerResponse): void {
  response.statusCode = 302;
  response.setHeader("location", "/login");
  response.end();
}

function getClientIp(request: IncomingMessage): string {
  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0]!.trim();
  }
  return request.socket.remoteAddress ?? "unknown";
}

function isAuthorizedRoute(method: string, pathname: string, role: AuthRole): boolean {
  const required = requiredRoleForRoute(method, pathname);
  return AUTH.roleAtLeast(role, required);
}

function requiredRoleForRoute(method: string, pathname: string): AuthRole {
  if (pathname === "/health") {
    return "viewer";
  }
  if (pathname === "/devices" && method === "GET") {
    return "viewer";
  }
  if (pathname === "/config/template/schema" && method === "GET") {
    return "viewer";
  }
  if (pathname === "/config/mcp" || pathname === "/config/templates" || /^\/config\/templates\/[^/]+\/compile$/.test(pathname)) {
    return method === "GET" ? "viewer" : "admin";
  }
  if (pathname.startsWith("/device/")) {
    return "operator";
  }
  if (/^\/devices\/[^/]+\/setup\/save$/.test(pathname)) {
    return "admin";
  }
  if (/^\/devices\/[^/]+\/config\/push$/.test(pathname)) {
    return "admin";
  }
  if (/^\/devices\/[^/]+\/jit\/kill$/.test(pathname)) {
    return "admin";
  }
  if (pathname.startsWith("/devices/") || pathname.startsWith("/session/")) {
    return "operator";
  }
  return "viewer";
}

function requiresCsrf(method: string, pathname: string): boolean {
  const normalized = method.toUpperCase();
  if (normalized === "GET" || normalized === "HEAD" || normalized === "OPTIONS") {
    return false;
  }
  if (pathname === "/auth/login") {
    return false;
  }
  return true;
}

function applySecurityHeaders(response: ServerResponse): void {
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("x-frame-options", "DENY");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader(
    "content-security-policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
  );
  if (AUTH.config.secureCookies) {
    response.setHeader("strict-transport-security", "max-age=31536000; includeSubDomains");
  }
}

function requestDirectory(
  deviceId: string,
  rootAlias: string,
  requestPath: string,
  limit: number,
  cursor: string | undefined,
): Promise<DirectoryResponseMessage> {
  const requestId = allocateRequestId();
  return sendRequest(deviceId, "ds", {
    v: WS_PROTOCOL_VERSION,
    t: "dr",
    i: requestId,
    r: rootAlias,
    p: requestPath,
    l: limit,
    k: cursor,
  }) as Promise<DirectoryResponseMessage>;
}

function startSession(
  deviceId: string,
  sessionId: string,
  folderPath: string,
  jitCredential?: SessionJitCredential,
): Promise<SessionResultMessage> {
  const requestId = allocateRequestId();
  const message: StartSessionMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "si",
    i: requestId,
    s: sessionId,
    p: folderPath,
    ...(jitCredential ? { j: jitCredential } : {}),
  };
  return sendRequest(deviceId, "sr", message) as Promise<SessionResultMessage>;
}

function terminateSession(deviceId: string, sessionId: string): Promise<SessionResultMessage> {
  const requestId = allocateRequestId();
  const message: TerminateSessionMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "st",
    i: requestId,
    s: sessionId,
  };
  return sendRequest(deviceId, "sr", message) as Promise<SessionResultMessage>;
}

function triggerJitKillSwitch(
  deviceId: string,
  sessionId: string | undefined,
  credentialRef: string | undefined,
  reason: string,
  closeTunnel: 0 | 1,
): Promise<JitKillSwitchResponseMessage> {
  const requestId = allocateRequestId();
  const message: JitKillSwitchRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "jk",
    i: requestId,
    ...(sessionId ? { s: sessionId } : {}),
    ...(credentialRef ? { r: credentialRef } : {}),
    x: closeTunnel,
    m: reason,
  };
  return sendRequest(deviceId, "jv", message) as Promise<JitKillSwitchResponseMessage>;
}

function getSessionStatus(deviceId: string, folderPath: string): Promise<SessionStatusResponseMessage> {
  const requestId = allocateRequestId();
  const message: SessionStatusRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "sq",
    i: requestId,
    p: folderPath,
  };
  return sendRequest(deviceId, "sv", message) as Promise<SessionStatusResponseMessage>;
}

function getSetupStatus(deviceId: string): Promise<SetupStatusResponseMessage> {
  const requestId = allocateRequestId();
  const message: SetupStatusRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "cf",
    i: requestId,
  };
  return sendRequest(deviceId, "cg", message) as Promise<SetupStatusResponseMessage>;
}

function saveSetupConfig(
  deviceId: string,
  request: {
    controlPlaneUrl: string;
    agentAuthToken: string;
    opencodeCommand: string;
    opencodeHost: string;
    opencodeStartPort: number;
    opencodeProviderId: string;
    opencodeModelId: string;
    requestTimeoutMs: number;
  },
): Promise<SetupSaveResponseMessage> {
  const requestId = allocateRequestId();
  const message: SetupSaveRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "cu",
    i: requestId,
    u: request.controlPlaneUrl,
    a: request.agentAuthToken,
    oc: request.opencodeCommand,
    oh: request.opencodeHost,
    os: request.opencodeStartPort,
    op: request.opencodeProviderId,
    om: request.opencodeModelId,
    rt: request.requestTimeoutMs,
  };
  return sendRequest(deviceId, "cv", message) as Promise<SetupSaveResponseMessage>;
}

function buildMcpRegistryKey(serverId: string, version: string): string {
  return `${serverId}@${version}`;
}

function buildTemplateKey(templateId: string, templateVersion: string): string {
  return `${templateId}@${templateVersion}`;
}

function resolveGatewayMcpUrl(gatewayId: string, serverPath: string): string | undefined {
  const base = MCP_GATEWAY_BASE_URLS.get(gatewayId);
  if (!base) {
    return undefined;
  }
  return `${base}/${serverPath.replace(/^\/+/, "")}`;
}

function getTemplateForCompile(templateId: string, requestedVersion: string): AgentTemplate {
  if (!/^[a-z0-9][a-z0-9_-]{2,63}$/.test(templateId)) {
    throw new ApiError(400, "invalid_template_id");
  }

  if (requestedVersion) {
    const key = buildTemplateKey(templateId, requestedVersion);
    const exact = templateRegistry.get(key);
    if (!exact) {
      throw new ApiError(404, "template_not_found");
    }
    return exact;
  }

  const candidates = Array.from(templateRegistry.values())
    .filter((template) => template.templateId === templateId)
    .sort((left, right) => right.templateVersion.localeCompare(left.templateVersion));
  const latest = candidates[0];
  if (!latest) {
    throw new ApiError(404, "template_not_found");
  }
  return latest;
}

async function pushCompiledConfig(
  deviceId: string,
  payload: {
    template: AgentTemplate;
    applyPath: string;
    digest: string;
    config: Record<string, unknown>;
    policyMode: "off" | "read-only" | "restricted";
    signatureAlgorithm: string;
    signature: string;
    phase?: "session-init" | "runtime";
    scope?: "session-init" | "full";
  },
): Promise<ConfigViewResponseMessage> {
  const requestId = allocateRequestId();
  const message: ConfigCheckPushRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "cc",
    i: requestId,
    k: "cfg",
    ...(payload.phase ? { ph: payload.phase } : {}),
    ...(payload.scope ? { sc: payload.scope } : {}),
    tid: payload.template.templateId,
    tv: payload.template.templateVersion,
    ts: Date.now(),
    ap: payload.applyPath,
    pd: payload.digest,
    ...(payload.signatureAlgorithm ? { alg: payload.signatureAlgorithm } : {}),
    ...(payload.signature ? { sg: payload.signature } : {}),
    ...(payload.policyMode ? { pm: payload.policyMode } : {}),
    cfg: JSON.parse(toCanonicalJson(payload.config)) as Record<string, unknown>,
  };

  configPushState.set(`${deviceId}:${requestId}`, {
    deviceId,
    requestId,
    templateId: payload.template.templateId,
    templateVersion: payload.template.templateVersion,
    status: "pending",
    digest: payload.digest,
    ...(payload.phase ? { phase: payload.phase } : {}),
    ...(payload.scope ? { scope: payload.scope } : {}),
    policyMode: payload.policyMode,
    appliedPath: payload.applyPath,
    respondedAt: Date.now(),
  });

  try {
    const response = await sendRequest<ConfigViewResponseMessage>(deviceId, "cvcfg", message);
    configPushState.set(`${deviceId}:${requestId}`, {
      deviceId,
      requestId,
      templateId: response.tid,
      templateVersion: response.tv,
      status: response.st,
      digest: response.pd,
      ...(response.ph ?? payload.phase ? { phase: response.ph ?? payload.phase } : {}),
      ...(response.sc ?? payload.scope ? { scope: response.sc ?? payload.scope } : {}),
      policyMode: response.pm ?? payload.policyMode,
      ...(response.ap ? { appliedPath: response.ap } : {}),
      ...(response.vd ? { violations: response.vd } : {}),
      ...(response.m ? { message: response.m } : {}),
      respondedAt: response.at,
    });
    return response;
  } catch (error) {
    const messageText = error instanceof Error ? error.message : "config_push_failed";
    configPushState.set(`${deviceId}:${requestId}`, {
      deviceId,
      requestId,
      templateId: payload.template.templateId,
      templateVersion: payload.template.templateVersion,
      status: "failed",
      digest: payload.digest,
      ...(payload.phase ? { phase: payload.phase } : {}),
      ...(payload.scope ? { scope: payload.scope } : {}),
      appliedPath: payload.applyPath,
      message: messageText,
      policyMode: payload.policyMode,
      respondedAt: Date.now(),
    });
    throw error;
  }
}

function startPrompt(deviceId: string, sessionId: string, streamId: string, prompt: string): { o: 1; x: string; i: number } {
  const ws = deviceRegistry.get(deviceId);
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    throw new ApiError(404, "device_not_connected");
  }

  const requestId = allocateRequestId();
  const message: StartPromptMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "sp",
    i: requestId,
    x: streamId,
    s: sessionId,
    p: prompt,
  };
  sendJson(ws, message);
  return { o: 1, x: streamId, i: requestId };
}

function requestSessionLogReplay(deviceId: string, streamId: string): void {
  const ws = deviceRegistry.get(deviceId);
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const request: SessionLogRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "sl",
    i: allocateRequestId(),
    x: streamId,
    l: clampInt(SESSION_LOG_REPLAY_LINES, SESSION_SNAPSHOT_MIN_LINES, SESSION_SNAPSHOT_MAX_LINES, SESSION_SNAPSHOT_MIN_LINES),
  };
  sendJson(ws, request);
}

function consumeSnapshotChunk(deviceId: string, chunk: StreamChunkMessage): boolean {
  const key = `${deviceId}:${chunk.x}`;
  const pending = pendingSnapshotPulls.get(key);
  if (!pending) {
    return false;
  }

  pending.parts.set(chunk.q, chunk.d);
  if (chunk.e !== 1) {
    return true;
  }

  clearTimeout(pending.timer);
  pendingSnapshotPulls.delete(key);
  const orderedParts = Array.from(pending.parts.entries())
    .sort((left, right) => left[0] - right[0])
    .map((entry) => entry[1]);
  pending.resolve(orderedParts.join(""));
  return true;
}

async function requestSnapshotTailFromAgent(deviceId: string, lineCount: number): Promise<string> {
  const ws = deviceRegistry.get(deviceId);
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    throw new ApiError(404, "device_not_connected");
  }

  const requestId = allocateRequestId();
  const streamId = randomToken(16);
  const key = `${deviceId}:${streamId}`;

  return new Promise<string>((resolve, reject) => {
    const timeout = setTimeout(() => {
      pendingSnapshotPulls.delete(key);
      reject(new ApiError(504, "snapshot_timeout"));
    }, REQUEST_TIMEOUT_MS);
    timeout.unref();

    pendingSnapshotPulls.set(key, {
      deviceId,
      streamId,
      parts: new Map<number, string>(),
      resolve,
      reject,
      timer: timeout,
    });

    const message: SessionLogRequestMessage = {
      v: WS_PROTOCOL_VERSION,
      t: "sl",
      i: requestId,
      x: streamId,
      l: clampInt(lineCount, SESSION_SNAPSHOT_MIN_LINES, SESSION_SNAPSHOT_MAX_LINES, SESSION_SNAPSHOT_MAX_LINES),
    };
    sendJson(ws, message);
  });
}

function mkdir(deviceId: string, rootAlias: string, requestPath: string): Promise<MkdirResponseMessage> {
  const requestId = allocateRequestId();
  const message: MkdirRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "md",
    i: requestId,
    r: rootAlias,
    p: requestPath,
  };
  return sendRequest(deviceId, "mr", message) as Promise<MkdirResponseMessage>;
}

function rmdir(deviceId: string, rootAlias: string, requestPath: string): Promise<RmdirResponseMessage> {
  const requestId = allocateRequestId();
  const message: RmdirRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "rd",
    i: requestId,
    r: rootAlias,
    p: requestPath,
  };
  return sendRequest(deviceId, "rr", message) as Promise<RmdirResponseMessage>;
}

function rename(deviceId: string, rootAlias: string, sourcePath: string, destPath: string): Promise<RenameResponseMessage> {
  const requestId = allocateRequestId();
  const message: RenameRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "rn",
    i: requestId,
    r: rootAlias,
    s: sourcePath,
    d: destPath,
  };
  return sendRequest(deviceId, "rp", message) as Promise<RenameResponseMessage>;
}

// Git Operations
function gitStatus(deviceId: string, rootAlias: string, requestPath: string): Promise<GitStatusResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitStatusRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gs",
    i: requestId,
    r: rootAlias,
    p: requestPath,
  };
  return sendRequest(deviceId, "gt", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitStatusResponseMessage>;
}

function gitInit(deviceId: string, rootAlias: string, requestPath: string): Promise<GitInitResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitInitRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gi",
    i: requestId,
    r: rootAlias,
    p: requestPath,
  };
  return sendRequest(deviceId, "gj", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitInitResponseMessage>;
}

function gitClone(deviceId: string, rootAlias: string, requestPath: string, repoUrl: string, branch?: string): Promise<GitCloneResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitCloneRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gk",
    i: requestId,
    r: rootAlias,
    p: requestPath,
    u: repoUrl,
    ...(branch ? { b: branch } : {}),
  };
  return sendRequest(deviceId, "gl", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitCloneResponseMessage>;
}

function gitAdd(deviceId: string, rootAlias: string, requestPath: string, files?: string, all?: 0 | 1): Promise<GitAddResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitAddRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "ga",
    i: requestId,
    r: rootAlias,
    p: requestPath,
    ...(files ? { f: files } : {}),
    ...(all ? { A: all } : {}),
  };
  return sendRequest(deviceId, "gb", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitAddResponseMessage>;
}

function gitCommit(deviceId: string, rootAlias: string, requestPath: string, messageText: string, amend?: 0 | 1): Promise<GitCommitResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitCommitRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gp",
    i: requestId,
    r: rootAlias,
    p: requestPath,
    m: messageText,
    ...(amend ? { a: amend } : {}),
  };
  return sendRequest(deviceId, "go", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitCommitResponseMessage>;
}

function gitPush(deviceId: string, rootAlias: string, requestPath: string, remote: string, branch?: string): Promise<GitPushResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitPushRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gh",
    i: requestId,
    r: rootAlias,
    p: requestPath,
    o: remote,
    ...(branch ? { b: branch } : {}),
  };
  return sendRequest(deviceId, "gd", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitPushResponseMessage>;
}

function gitPull(deviceId: string, rootAlias: string, requestPath: string, remote: string, branch?: string): Promise<GitPullResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitPullRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gm",
    i: requestId,
    r: rootAlias,
    p: requestPath,
    o: remote,
    ...(branch ? { b: branch } : {}),
  };
  return sendRequest(deviceId, "gn", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitPullResponseMessage>;
}

function gitBranch(deviceId: string, rootAlias: string, requestPath: string, action: "list" | "create" | "delete", branchName?: string): Promise<GitBranchResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitBranchRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gc",
    i: requestId,
    r: rootAlias,
    p: requestPath,
    a: action,
    ...(branchName ? { n: branchName } : {}),
  };
  return sendRequest(deviceId, "gu", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitBranchResponseMessage>;
}

function gitCheckout(deviceId: string, rootAlias: string, requestPath: string, branch: string, create?: 0 | 1): Promise<GitCheckoutResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitCheckoutRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gx",
    i: requestId,
    r: rootAlias,
    p: requestPath,
    b: branch,
    ...(create ? { c: create } : {}),
  };
  return sendRequest(deviceId, "gy", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitCheckoutResponseMessage>;
}

function gitConfig(
  deviceId: string,
  rootAlias: string,
  requestPath: string,
  action: "get" | "set",
  name?: string,
  email?: string,
  global?: 0 | 1,
  credentialManager?: 0 | 1,
): Promise<GitConfigResponseMessage> {
  const requestId = allocateRequestId();
  const message: GitConfigRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "gf",
    i: requestId,
    r: rootAlias,
    p: requestPath,
    a: action,
    ...(name ? { n: name } : {}),
    ...(email ? { e: email } : {}),
    ...(global ? { g: global } : {}),
    ...(credentialManager ? { cm: credentialManager } : {}),
  };
  return sendRequest(deviceId, "gv", message, GIT_REQUEST_TIMEOUT_MS) as Promise<GitConfigResponseMessage>;
}

type ProxiedHttpResult = {
  status: number;
  statusText: string;
  headers: ProxyHeaderEntry[];
  body: Buffer;
};

async function proxyHttpToDevice(
  deviceId: string,
  port: number,
  method: string,
  requestPath: string,
  requestHeaders: IncomingMessage["headers"],
  body: Buffer,
): Promise<ProxiedHttpResult> {
  const requestId = allocateRequestId();
  const headers = toProxyRequestHeaders(requestHeaders);
  const message: PortProxyRequestMessage = {
    v: WS_PROTOCOL_VERSION,
    t: "pr",
    i: requestId,
    p: port,
    m: method.toUpperCase(),
    u: requestPath,
    h: headers,
    b: body.length > 0 ? body.toString("base64") : "",
  };

  const response = await sendRequest<PortProxyResponseMessage>(deviceId, "pv", message, PORT_PROXY_REQUEST_TIMEOUT_MS);
  if (response.o !== 1) {
    throw new ApiError(502, response.m || "proxy_failed");
  }

  const responseBody = response.b ? Buffer.from(response.b, "base64") : Buffer.alloc(0);
  return {
    status: response.sc ?? 502,
    statusText: response.sm ?? "proxy",
    headers: response.h ?? [],
    body: responseBody,
  };
}

function sendRequest<T, M extends { i: number } = { i: number }>(
  deviceId: string,
  expectedType: "ds" | "sr" | "sv" | "cg" | "cv" | "cvcfg" | "jv" | "mr" | "rr" | "rp" | "gt" | "gj" | "gl" | "gb" | "go" | "gd" | "gn" | "gu" | "gy" | "gv" | "pv",
  message: M,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<T> {
  const ws = deviceRegistry.get(deviceId);
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    throw new ApiError(404, "device_not_connected");
  }

  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingRequests.delete(message.i);
      reject(new ApiError(504, "request_timeout"));
    }, timeoutMs);
    timer.unref();

    pendingRequests.set(message.i, { deviceId, expectedType, resolve, reject, timer });
    sendJson(ws, message);
  });
}

function settlePending(
  requestId: number,
  deviceId: string,
  type: "ds" | "sr" | "sv" | "cg" | "cv" | "cvcfg" | "jv" | "mr" | "rr" | "rp" | "gt" | "gj" | "gl" | "gb" | "go" | "gd" | "gn" | "gu" | "gy" | "gv" | "pv",
  payload:
    | DirectoryResponseMessage
    | SessionResultMessage
    | SessionStatusResponseMessage
    | SetupStatusResponseMessage
    | SetupSaveResponseMessage
    | MkdirResponseMessage
    | RmdirResponseMessage
    | RenameResponseMessage
    | GitStatusResponseMessage
    | GitInitResponseMessage
    | GitCloneResponseMessage
    | GitAddResponseMessage
    | GitCommitResponseMessage
    | GitPushResponseMessage
    | GitPullResponseMessage
    | GitBranchResponseMessage
    | GitCheckoutResponseMessage
    | GitConfigResponseMessage
    | ConfigViewResponseMessage
    | JitKillSwitchResponseMessage
    | PortProxyResponseMessage,
): void {
  const pending = pendingRequests.get(requestId);
  if (!pending) {
    return;
  }
  if (pending.deviceId !== deviceId || pending.expectedType !== type) {
    return;
  }
  clearTimeout(pending.timer);
  pendingRequests.delete(requestId);
  pending.resolve(payload);
}

function failPending(requestId: number, deviceId: string, reason: string): boolean {
  const pending = pendingRequests.get(requestId);
  if (!pending || pending.deviceId !== deviceId) {
    return false;
  }
  clearTimeout(pending.timer);
  pendingRequests.delete(requestId);
  pending.reject(new ApiError(502, reason));
  return true;
}

function rejectPendingForDevice(deviceId: string, reason: string): void {
  for (const [requestId, pending] of pendingRequests.entries()) {
    if (pending.deviceId !== deviceId) {
      continue;
    }
    clearTimeout(pending.timer);
    pendingRequests.delete(requestId);
    pending.reject(new ApiError(502, reason));
  }
}

function allocateRequestId(): number {
  const requestId = nextRequestId;
  nextRequestId += 1;
  if (nextRequestId > 0xffffffff) {
    nextRequestId = 1;
  }
  return requestId;
}

function readSessionId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(value)) {
    throw new ApiError(400, "invalid_session_id");
  }
  return value;
}

function readStreamId(value: unknown): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{8,24}$/.test(value)) {
    throw new ApiError(400, "invalid_stream_id");
  }
  return value;
}

function readPrompt(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApiError(400, "invalid_prompt");
  }
  const prompt = value.trim();
  if (!prompt || prompt.length > MAX_PROMPT_CHARS) {
    throw new ApiError(400, "invalid_prompt");
  }
  return prompt;
}

function readString(value: unknown, fallback: string): string {
  if (typeof value === "string") {
    return value;
  }
  return fallback;
}

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    return fallback;
  }
  if (value < min) {
    return min;
  }
  if (value > max) {
    return max;
  }
  return value;
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
  allowlist.add(JIT_CREDENTIAL_DEFAULT_ENV_VAR);
  allowlist.add("OPENCODE_JIT_TOKEN_EXPIRES_AT");
  allowlist.add("OPENCODE_JIT_SCOPE");
  return allowlist;
}

function isJitEnvVarName(value: string): boolean {
  return /^[A-Z_][A-Z0-9_]{1,63}$/.test(value);
}

function isJitAllowedEnvVarName(value: string): boolean {
  return isJitEnvVarName(value) && JIT_CREDENTIAL_ENV_ALLOWLIST.has(value);
}

function parseJitEnvPairsFromBody(value: unknown): Array<[string, string]> {
  if (value === undefined) {
    return [];
  }

  const pairs: Array<[string, string]> = [];
  if (Array.isArray(value)) {
    for (const entry of value) {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || typeof entry[1] !== "string") {
        throw new ApiError(400, "invalid_jit_env_pairs");
      }
      pairs.push([entry[0], entry[1]]);
    }
  } else if (isObject(value)) {
    for (const [name, raw] of Object.entries(value)) {
      if (typeof raw !== "string") {
        throw new ApiError(400, "invalid_jit_env_pairs");
      }
      pairs.push([name, raw]);
    }
  } else {
    throw new ApiError(400, "invalid_jit_env_pairs");
  }

  if (pairs.length > JIT_CREDENTIAL_ENV_MAX_PAIRS) {
    throw new ApiError(400, "jit_env_pairs_too_many");
  }

  const seen = new Set<string>();
  for (const [name, rawValue] of pairs) {
    if (!isJitAllowedEnvVarName(name)) {
      throw new ApiError(400, "invalid_jit_env_pair_name");
    }
    if (seen.has(name)) {
      throw new ApiError(400, "duplicate_jit_env_pair_name");
    }
    seen.add(name);
    if (!rawValue || rawValue.includes("\0") || Buffer.byteLength(rawValue, "utf8") > JIT_CREDENTIAL_ENV_MAX_VALUE_BYTES) {
      throw new ApiError(400, "invalid_jit_env_pair_value");
    }
  }
  return pairs;
}

function toProxyRequestHeaders(headers: IncomingMessage["headers"]): ProxyHeaderEntry[] {
  const entries: ProxyHeaderEntry[] = [];
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    if (!isAllowedProxyRequestHeader(name)) {
      continue;
    }
    if (Array.isArray(rawValue)) {
      for (const value of rawValue) {
        if (typeof value !== "string") {
          continue;
        }
        entries.push([name, value]);
      }
      continue;
    }
    if (typeof rawValue === "string") {
      entries.push([name, rawValue]);
    }
  }
  return entries.slice(0, PORT_PROXY_MAX_HEADER_COUNT);
}

function isAllowedProxyRequestHeader(name: string): boolean {
  if (name === "host" || name === "content-length" || name === "connection" || name === "cookie") {
    return false;
  }
  if (name.startsWith("sec-websocket")) {
    return false;
  }
  return true;
}

async function readRawBody(request: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer);
    total += buffer.byteLength;
    if (total > maxBytes) {
      throw new ApiError(413, "payload_too_large");
    }
    chunks.push(buffer);
  }
  return chunks.length > 0 ? Buffer.concat(chunks) : Buffer.alloc(0);
}

function buildSessionJitCredential(
  body: Record<string, unknown>,
  deviceId: string,
  sessionId: string,
): SessionJitCredential {
  const jitPayload = isObject(body.jit) ? body.jit : {};
  const tokenFromBody = readString(jitPayload.token, readString(body.jitToken, "")).trim();
  const scope = readString(jitPayload.scope, readString(body.jitScope, JIT_CREDENTIAL_DEFAULT_SCOPE)).trim() || JIT_CREDENTIAL_DEFAULT_SCOPE;
  const envVar = readString(jitPayload.env, readString(body.jitEnv, JIT_CREDENTIAL_DEFAULT_ENV_VAR)).trim() || JIT_CREDENTIAL_DEFAULT_ENV_VAR;
  const credentialRef = readString(jitPayload.ref, readString(body.jitRef, randomToken(12))).trim() || randomToken(12);
  const envPairsRaw = isObject(jitPayload) ? jitPayload.envPairs : body.jitEnvPairs;
  const envPairs = parseJitEnvPairsFromBody(envPairsRaw);

  if (!isJitAllowedEnvVarName(envVar)) {
    throw new ApiError(400, "invalid_jit_env");
  }
  if (scope.length > 128) {
    throw new ApiError(400, "invalid_jit_scope");
  }
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(credentialRef)) {
    throw new ApiError(400, "invalid_jit_ref");
  }

  const ttlSeconds = clampInt(
    isObject(jitPayload) ? jitPayload.ttlSec : undefined,
    JIT_CREDENTIAL_MIN_TTL_SECONDS,
    JIT_CREDENTIAL_MAX_TTL_SECONDS,
    clampInt(body.jitTtlSec, JIT_CREDENTIAL_MIN_TTL_SECONDS, JIT_CREDENTIAL_MAX_TTL_SECONDS, JIT_CREDENTIAL_DEFAULT_TTL_SECONDS),
  );

  const expiresAtFromBody = clampInt(
    isObject(jitPayload) ? jitPayload.expiresAt : undefined,
    Date.now() + JIT_CREDENTIAL_MIN_TTL_SECONDS * 1000,
    Date.now() + JIT_CREDENTIAL_MAX_TTL_SECONDS * 1000,
    clampInt(body.jitExpiresAt, Date.now() + JIT_CREDENTIAL_MIN_TTL_SECONDS * 1000, Date.now() + JIT_CREDENTIAL_MAX_TTL_SECONDS * 1000, 0),
  );
  const expiresAt = expiresAtFromBody > 0 ? expiresAtFromBody : Date.now() + ttlSeconds * 1000;

  const token = tokenFromBody || mintJitCredentialToken(deviceId, sessionId, scope, expiresAt);
  if (token.length < 16 || token.length > 2048) {
    throw new ApiError(400, "invalid_jit_token");
  }

  return {
    t: token,
    e: expiresAt,
    s: scope,
    n: envVar,
    r: credentialRef,
    ...(envPairs.length > 0 ? { v: envPairs } : {}),
  };
}

function mintJitCredentialToken(deviceId: string, sessionId: string, scope: string, expiresAt: number): string {
  const payload = {
    d: deviceId,
    s: sessionId,
    sc: scope,
    exp: expiresAt,
    n: randomToken(12),
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  if (!JIT_CREDENTIAL_SIGNING_KEY) {
    return `jit.${encodedPayload}.${randomToken(24)}`;
  }
  const signature = sign(JIT_CREDENTIAL_SIGNING_KEY, encodedPayload);
  return `jit.${encodedPayload}.${signature}`;
}

async function readJsonBody(request: IncomingMessage, maxBytes: number): Promise<Record<string, unknown>> {
  const rawBuffer = await readRawBody(request, maxBytes);
  if (rawBuffer.length === 0) {
    return {};
  }
  const raw = rawBuffer.toString("utf8");
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isObject(parsed)) {
      throw new ApiError(400, "invalid_json_body");
    }
    return parsed;
  } catch {
    throw new ApiError(400, "invalid_json_body");
  }
}

function sendProxyResponse(
  response: ServerResponse,
  statusCode: number,
  statusText: string,
  headers: ProxyHeaderEntry[],
  body: Buffer,
): void {
  response.statusCode = statusCode;
  response.statusMessage = statusText;
  for (const [name, value] of headers) {
    const lower = name.toLowerCase();
    if (lower === "connection" || lower === "transfer-encoding" || lower === "content-length" || lower === "set-cookie") {
      continue;
    }
    response.setHeader(name, value);
  }
  response.setHeader("content-length", body.byteLength);
  response.end(body);
}

function parseSnapshotJsonLines(raw: string): Array<Record<string, unknown>> {
  const entries: Array<Record<string, unknown>> = [];
  const lines = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (isObject(parsed)) {
        entries.push(normalizeSnapshotEntry(parsed));
      }
    } catch {
      entries.push({ ts: new Date().toISOString(), k: "legacy", src: "session", m: trimmed });
    }
  }
  return entries;
}

function normalizeSnapshotEntry(entry: Record<string, unknown>): Record<string, unknown> {
  const normalized: Record<string, unknown> = {
    ts: shortString(entry.ts, 64) ? entry.ts : new Date().toISOString(),
    k: entry.k === "meta" || entry.k === "log" ? entry.k : "legacy",
  };

  if (entry.src === "opencode" || entry.src === "git" || entry.src === "session") {
    normalized.src = entry.src;
  } else {
    normalized.src = "session";
  }
  if (shortString(entry.m, 4000)) {
    normalized.m = entry.m;
  }
  if (shortString(entry.sid, 64)) {
    normalized.sid = entry.sid;
  }
  if (shortString(entry.fp, 2048)) {
    normalized.fp = entry.fp;
  }
  if (isObject(entry.md)) {
    normalized.md = entry.md;
  }

  return normalized;
}

function sendJsonResponse(response: ServerResponse, statusCode: number, payload: object): void {
  const body = JSON.stringify(payload);
  response.statusCode = statusCode;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.end(body);
}

function sendDirectoryError(response: ServerResponse, error: unknown): void {
  if (error instanceof ApiError) {
    if (error.message === "remote error: PATH" || error.message === "remote error: ROOT") {
      sendJsonResponse(response, 400, { error: error.message });
      return;
    }
    sendJsonResponse(response, 500, { error: error.message });
    return;
  }
  sendJsonResponse(response, 500, { error: "directory_request_failed" });
}

async function sendStaticAsset(response: ServerResponse, fileName: string, contentType: string): Promise<void> {
  const filePath = path.join(PUBLIC_ROOT, fileName);
  const body = await readFile(filePath);
  response.statusCode = 200;
  response.setHeader("content-type", contentType);
  response.setHeader("content-length", body.byteLength);
  response.end(body);
}

function parseHandshakeInit(value: unknown): HandshakeInitMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "d", "at", "ak", "n", "ts", "m", "c", "hn", "os", "av"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "h1") {
    return null;
  }
  if (!matches(value.d, /^[A-Za-z0-9_-]{12,32}$/)) {
    return null;
  }
  if (value.at !== undefined && !shortString(value.at, 256)) {
    return null;
  }
  if (value.ak !== undefined && !matches(value.ak, /^[A-Za-z0-9_-]{16,32}$/)) {
    return null;
  }
  if (value.at === undefined && value.ak === undefined) {
    return null;
  }
  if (!matches(value.n, /^[A-Za-z0-9_-]{16,24}$/)) {
    return null;
  }
  if (!isInteger(value.ts)) {
    return null;
  }
  if (!matches(value.m, /^[A-Za-z0-9_-]{43}$/)) {
    return null;
  }
  if (value.c !== undefined && !isUint32(value.c)) {
    return null;
  }
  if (value.hn !== undefined && !shortString(value.hn, 64)) {
    return null;
  }
  if (value.os !== undefined && !shortString(value.os, 64)) {
    return null;
  }
  if (value.av !== undefined && !shortString(value.av, 32)) {
    return null;
  }
  return value as unknown as HandshakeInitMessage;
}

function parseHandshakeProtocolVersion(value: unknown): number | null {
  if (!isObject(value) || value.t !== "h1" || !isInteger(value.v)) {
    return null;
  }
  return value.v;
}

function parseTelemetryPing(value: unknown): TelemetryPingMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "u", "r", "a"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "p") {
    return null;
  }
  if (!isUint32(value.u) || !isUint32(value.r)) {
    return null;
  }
  if (!isInteger(value.a) || value.a < 0 || value.a > 65535) {
    return null;
  }
  return value as unknown as TelemetryPingMessage;
}

function parsePortList(value: unknown): PortListMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "p"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "pl") {
    return null;
  }
  if (!Array.isArray(value.p) || value.p.length > 64) {
    return null;
  }
  const ports: number[] = [];
  for (const entry of value.p) {
    if (!isInteger(entry) || entry < 1 || entry > 65535) {
      return null;
    }
    ports.push(entry);
  }
  return { v: WS_PROTOCOL_VERSION, t: "pl", p: ports };
}

function parseDirectoryResponse(value: unknown): DirectoryResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "k", "e"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "ds") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.k !== undefined && !shortString(value.k, 128)) {
    return null;
  }
  if (!Array.isArray(value.e) || value.e.length > MAX_DIRECTORY_LIMIT) {
    return null;
  }
  for (const entry of value.e) {
    if (!isDirectoryEntry(entry)) {
      return null;
    }
  }
  return value as unknown as DirectoryResponseMessage;
}

function parseSessionResult(value: unknown): SessionResultMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "s", "o", "m", "u"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "sr") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (!matches(value.s, /^[A-Za-z0-9_-]{1,64}$/)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  if (value.m !== undefined && !shortString(value.m, 96)) {
    return null;
  }
  if (value.u !== undefined && !shortString(value.u, 1024)) {
    return null;
  }
  return value as unknown as SessionResultMessage;
}

function parseSessionStatusResponse(value: unknown): SessionStatusResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "p", "d", "u", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "sv") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  if (value.p !== undefined && (!isInteger(value.p) || value.p < 1 || value.p > 65535)) {
    return null;
  }
  if (value.d !== undefined && (!isInteger(value.d) || value.d < 1 || value.d > 0x7fffffff)) {
    return null;
  }
  if (value.u !== undefined && !shortString(value.u, 512)) {
    return null;
  }
  if (value.m !== undefined && !shortString(value.m, 96)) {
    return null;
  }
  return value as unknown as SessionStatusResponseMessage;
}

function parseSetupStatusResponse(value: unknown): SetupStatusResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "c", "u", "a", "oc", "oh", "os", "op", "om", "rt", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "cg") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  if (value.c !== undefined && value.c !== 0 && value.c !== 1) {
    return null;
  }
  if (value.u !== undefined && !shortString(value.u, 512)) {
    return null;
  }
  if (value.a !== undefined && value.a !== 0 && value.a !== 1) {
    return null;
  }
  if (value.oc !== undefined && !shortString(value.oc, 256)) {
    return null;
  }
  if (value.oh !== undefined && !shortString(value.oh, 128)) {
    return null;
  }
  if (value.os !== undefined && (!isInteger(value.os) || value.os < 1 || value.os > 65535)) {
    return null;
  }
  if (value.op !== undefined && !shortString(value.op, 128)) {
    return null;
  }
  if (value.om !== undefined && !shortString(value.om, 128)) {
    return null;
  }
  if (value.rt !== undefined && (!isInteger(value.rt) || value.rt < 1000 || value.rt > 120000)) {
    return null;
  }
  if (value.m !== undefined && !shortString(value.m, 96)) {
    return null;
  }
  return value as unknown as SetupStatusResponseMessage;
}

function parseSetupSaveResponse(value: unknown): SetupSaveResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "k", "o", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "cv") {
    return null;
  }
  if (value.k !== undefined && value.k !== "setup") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  if (value.m !== undefined && !shortString(value.m, 96)) {
    return null;
  }
  return value as unknown as SetupSaveResponseMessage;
}

function parseConfigViewResponse(value: unknown): ConfigViewResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "k", "ph", "sc", "o", "tid", "tv", "st", "pd", "at", "ap", "vd", "alg", "sg", "pm", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "cv" || value.k !== "cfg") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
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
  if (value.st !== "applied" && value.st !== "rejected") {
    return null;
  }
  if (!matches(value.pd, /^[A-Za-z0-9_-]{43}$/)) {
    return null;
  }
  if (!isInteger(value.at) || value.at < 0) {
    return null;
  }
  if (value.ap !== undefined && !shortString(value.ap, 256)) {
    return null;
  }
  if (value.vd !== undefined) {
    if (!Array.isArray(value.vd) || value.vd.length > 32) {
      return null;
    }
    for (const violation of value.vd) {
      if (!shortString(violation, 160)) {
        return null;
      }
    }
  }
  if (value.alg !== undefined && !shortString(value.alg, 64)) {
    return null;
  }
  if (value.sg !== undefined && !shortString(value.sg, 512)) {
    return null;
  }
  if (value.pm !== undefined && value.pm !== "off" && value.pm !== "read-only" && value.pm !== "restricted") {
    return null;
  }
  if (value.m !== undefined && !shortString(value.m, 256)) {
    return null;
  }
  return value as unknown as ConfigViewResponseMessage;
}

function parseJitKillSwitchResponse(value: unknown): JitKillSwitchResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "a", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "jv") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  if (!isUint32(value.a)) {
    return null;
  }
  if (value.m !== undefined && !shortString(value.m, 160)) {
    return null;
  }
  return value as unknown as JitKillSwitchResponseMessage;
}

function parseMkdirResponse(value: unknown): MkdirResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "mr") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as MkdirResponseMessage;
}

function parseRmdirResponse(value: unknown): RmdirResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "rr") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as RmdirResponseMessage;
}

function parseRenameResponse(value: unknown): RenameResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "rp") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as RenameResponseMessage;
}

// Git Response Parsers
function parseGitStatusResponse(value: unknown): GitStatusResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "b", "a", "m", "u", "d", "c", "e"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gt") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as GitStatusResponseMessage;
}

function parseGitInitResponse(value: unknown): GitInitResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gj") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as GitInitResponseMessage;
}

function parseGitCloneResponse(value: unknown): GitCloneResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gl") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as GitCloneResponseMessage;
}

function parseGitAddResponse(value: unknown): GitAddResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gb") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as GitAddResponseMessage;
}

function parseGitCommitResponse(value: unknown): GitCommitResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "h", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "go") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as GitCommitResponseMessage;
}

function parseGitPushResponse(value: unknown): GitPushResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gd") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as GitPushResponseMessage;
}

function parseGitPullResponse(value: unknown): GitPullResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gn") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as GitPullResponseMessage;
}

function parseGitBranchResponse(value: unknown): GitBranchResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "b", "c", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gu") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as GitBranchResponseMessage;
}

function parseGitCheckoutResponse(value: unknown): GitCheckoutResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gy") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  return value as unknown as GitCheckoutResponseMessage;
}

function parseGitConfigResponse(value: unknown): GitConfigResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "n", "e", "h", "a", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gv") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  if (value.n !== undefined && !shortString(value.n, 256)) {
    return null;
  }
  if (value.e !== undefined && !shortString(value.e, 256)) {
    return null;
  }
  if (value.h !== undefined && !shortString(value.h, 128)) {
    return null;
  }
  if (value.a !== undefined && value.a !== 0 && value.a !== 1) {
    return null;
  }
  if (value.m !== undefined && (typeof value.m !== "string" || value.m.length > 1200)) {
    return null;
  }
  return value as unknown as GitConfigResponseMessage;
}

function parseGitLogMessage(value: unknown): GitLogMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "s", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "gq") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.s !== "meta" && value.s !== "out" && value.s !== "err") {
    return null;
  }
  if (!shortString(value.m, 500)) {
    return null;
  }
  return value as unknown as GitLogMessage;
}

function parseStreamChunk(value: unknown): StreamChunkMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "x", "q", "e", "d"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "sc") {
    return null;
  }
  if (!matches(value.x, /^[A-Za-z0-9_-]{8,24}$/)) {
    return null;
  }
  if (!isUint32(value.q)) {
    return null;
  }
  if (value.e !== 0 && value.e !== 1) {
    return null;
  }
  if (typeof value.d !== "string" || value.d.length > MAX_STREAM_CHUNK_BYTES) {
    return null;
  }
  return value as unknown as StreamChunkMessage;
}

function parsePortProxyResponse(value: unknown): PortProxyResponseMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (!hasOnlyKeys(value, ["v", "t", "i", "o", "sc", "sm", "h", "b", "m"])) {
    return null;
  }
  if (value.v !== WS_PROTOCOL_VERSION || value.t !== "pv") {
    return null;
  }
  if (!isUint32(value.i)) {
    return null;
  }
  if (value.o !== 0 && value.o !== 1) {
    return null;
  }
  if (value.sc !== undefined && (!isInteger(value.sc) || value.sc < 100 || value.sc > 599)) {
    return null;
  }
  if (value.sm !== undefined && !shortString(value.sm, 128)) {
    return null;
  }
  if (value.h !== undefined && (!Array.isArray(value.h) || value.h.length > PORT_PROXY_MAX_HEADER_COUNT || !value.h.every(isProxyHeaderEntry))) {
    return null;
  }
  if (value.b !== undefined && (typeof value.b !== "string" || value.b.length > 3_000_000)) {
    return null;
  }
  if (value.m !== undefined && !shortString(value.m, 256)) {
    return null;
  }
  return value as unknown as PortProxyResponseMessage;
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
  if (value.m !== undefined && !shortString(value.m, 256)) {
    return null;
  }
  return value as unknown as ErrorMessage;
}

function isDirectoryEntry(value: unknown): boolean {
  if (!Array.isArray(value)) {
    return false;
  }
  if (value[0] === "d") {
    return value.length === 3 && shortString(value[1], 255) && isUint32(value[2]);
  }
  if (value[0] === "f") {
    return value.length === 4 && shortString(value[1], 255) && isUint32(value[2]) && isUint32(value[3]);
  }
  return false;
}

function sendError(ws: WebSocket, code: ErrorCode, requestId?: number, message?: string): void {
  sendJson(ws, {
    v: WS_PROTOCOL_VERSION,
    t: "e",
    ...(requestId !== undefined ? { i: requestId } : {}),
    c: code,
    ...(message ? { m: message } : {}),
  });
}

function routeStreamChunk(deviceId: string, chunk: StreamChunkMessage): void {
  for (const ws of uiClients) {
    if (ws.readyState !== WebSocket.OPEN) {
      continue;
    }
    if (ws.bufferedAmount > UI_MAX_BUFFER_BYTES) {
      ws.terminate();
      uiClients.delete(ws);
      uiClientSubscriptions.delete(ws);
      continue;
    }
    const subscription = uiClientSubscriptions.get(ws);
    if (!subscription || subscription.deviceId !== deviceId || subscription.streamId !== chunk.x) {
      continue;
    }
    sendUiJson(ws, { t: "chunk", d: deviceId, x: chunk.x, q: chunk.q, e: chunk.e, c: chunk.d });
  }
}

function routeUiError(deviceId: string, requestId: number | undefined, code: ErrorCode): void {
  for (const ws of uiClients) {
    if (ws.readyState !== WebSocket.OPEN) {
      continue;
    }
    const subscription = uiClientSubscriptions.get(ws);
    if (!subscription || subscription.deviceId !== deviceId) {
      continue;
    }
    sendUiJson(ws, { t: "err", d: deviceId, i: requestId, c: code });
  }
}

function routeUiGitLog(deviceId: string, payload: GitLogMessage): void {
  for (const ws of uiClients) {
    if (ws.readyState !== WebSocket.OPEN) {
      continue;
    }
    sendUiJson(ws, { t: "gitlog", d: deviceId, i: payload.i, s: payload.s, m: payload.m });
  }
}

function sendUiJson(ws: WebSocket, payload: object): void {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function sendJson(ws: WebSocket, message: object): void {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
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

function parseValidTokens(raw: string): Set<string> {
  const tokens = new Set<string>();
  for (const part of raw.split(",")) {
    const token = part.trim();
    if (!token) {
      continue;
    }
    tokens.add(token);
  }
  return tokens;
}

function parseGatewayBaseUrls(raw: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }
    const divider = trimmed.indexOf("=");
    if (divider <= 0) {
      continue;
    }
    const gatewayId = trimmed.slice(0, divider).trim();
    const baseUrl = trimmed.slice(divider + 1).trim().replace(/\/+$/, "");
    if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(gatewayId)) {
      continue;
    }
    try {
      const parsed = new URL(baseUrl);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        continue;
      }
      map.set(gatewayId, parsed.toString().replace(/\/+$/, ""));
    } catch {
      continue;
    }
  }
  return map;
}

function buildTokenKeyIdMap(tokens: Set<string>): Map<string, string> {
  const lookup = new Map<string, string>();
  for (const token of tokens) {
    lookup.set(deriveAuthKeyId(token), token);
  }
  return lookup;
}

function resolveHandshakeToken(message: HandshakeInitMessage): string | null {
  if (message.ak) {
    return validTokenByKeyId.get(message.ak) ?? null;
  }
  if (message.at && validTokens.has(message.at)) {
    return message.at;
  }
  return null;
}

function canonicalH1(message: HandshakeInitMessage): string {
  if (message.ak) {
    return `h1|1|${message.d}|${message.n}|${message.ts}|ak:${message.ak}`;
  }
  return `h1|1|${message.d}|${message.n}|${message.ts}|at:${message.at ?? ""}`;
}

function canonicalH1Legacy(message: HandshakeInitMessage): string {
  return `h1|1|${message.d}|${message.n}|${message.ts}|${message.at ?? ""}`;
}

function deriveAuthKeyId(secret: string): string {
  return createHash("sha256").update(secret).digest("base64url").slice(0, 24);
}

function canonicalH2(sid: string, nonce: string, hb: number, mx: number, h1Nonce: string): string {
  return `h2|1|${sid}|${nonce}|${hb}|${mx}|${h1Nonce}`;
}

function sign(secret: string, value: string): string {
  return createHmac("sha256", secret).update(value).digest("base64url");
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

function shortString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
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

function pruneNonceCache(): void {
  const now = Date.now();
  for (const [nonce, expiresAt] of recentNonces.entries()) {
    if (expiresAt <= now) {
      recentNonces.delete(nonce);
    }
  }
}

function redactSensitiveText(value: string): string {
  let output = value;
  for (const [key, token] of validTokenByKeyId.entries()) {
    output = output.split(token).join(`***${key}***`);
  }
  output = output.replace(/\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|AUTH|API_KEY)[A-Z0-9_]*)\s*=\s*([^\s]+)/gi, "$1=***REDACTED***");
  return output;
}

function log(message: string): void {
  process.stdout.write(`[control-plane] ${new Date().toISOString()} ${redactSensitiveText(message)}\n`);
}

function auditLog(event: string, details: Record<string, unknown>): void {
  const payload = JSON.stringify({
    ts: new Date().toISOString(),
    event,
    ...details,
  });
  process.stdout.write(`[audit] ${redactSensitiveText(payload)}\n`);
}

class ApiError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type DeviceSocketState = {
  deviceId: string;
  sid: string;
};

type DeviceMeta = {
  sid: string;
  connectedAt: number;
  lastSeenAt: number;
  hostname?: string;
  os?: string;
  agentVersion?: string;
  rss: number;
  uptime: number;
  exposedPorts: number[];
  exposedPortsUpdatedAt: number;
};

type PendingRequest = {
  deviceId: string;
  expectedType: "ds" | "sr" | "sv" | "cg" | "cv" | "cvcfg" | "jv" | "mr" | "rr" | "rp" | "gt" | "gj" | "gl" | "gb" | "go" | "gd" | "gn" | "gu" | "gy" | "gv" | "pv";
  resolve: (value: any) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

type ConfigPushStatus = {
  deviceId: string;
  requestId: number;
  templateId: string;
  templateVersion: string;
  status: "pending" | "applied" | "rejected" | "failed";
  digest: string;
  phase?: "session-init" | "runtime";
  scope?: "session-init" | "full";
  policyMode?: "off" | "read-only" | "restricted";
  appliedPath?: string;
  violations?: string[];
  message?: string;
  respondedAt: number;
};

type UiSubscription = {
  deviceId: string;
  streamId: string;
};

type PortOwnership = {
  principalId: string;
  sessionId: string;
  assignedAt: number;
};

type PendingSnapshotPull = {
  deviceId: string;
  streamId: string;
  parts: Map<number, string>;
  resolve: (value: string) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

if (validTokens.size === 0) {
  log("warning: VALID_TOKENS is empty; all handshakes will be rejected");
}

if (AUTH.config.mode === "local" && !process.env.AUTH_OWNER_EMAIL && !process.env.AUTH_LOCAL_USERS) {
  log("warning: local auth is enabled but no local users are configured");
}
