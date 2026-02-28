export const WS_PROTOCOL_VERSION = 1 as const;

export type WsMessageType = "h1" | "h2" | "p" | "pl" | "dr" | "ds" | "sc" | "sa" | "si" | "st" | "sr" | "sq" | "sv" | "sl" | "pr" | "pv" | "cf" | "cg" | "cu" | "cc" | "cv" | "jk" | "jv" | "sp" | "md" | "mr" | "rd" | "rr" | "rn" | "rp" | "gi" | "gj" | "gk" | "gs" | "ga" | "gt" | "gp" | "gl" | "gm" | "gn" | "gb" | "go" | "gh" | "gd" | "gc" | "gu" | "gx" | "gy" | "gf" | "gv" | "gq" | "e";

export interface WsEnvelope {
  v: typeof WS_PROTOCOL_VERSION;
  t: WsMessageType;
  i?: number;
}

export interface HandshakeInitMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "h1";
  d: string;
  at?: string;
  ak?: string;
  n: string;
  ts: number;
  m: string;
  c?: number;
  hn?: string;
  os?: string;
  av?: string;
}

export interface HandshakeAckMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "h2";
  s: string;
  n: string;
  hb: number;
  mx: number;
  m: string;
}

export interface TelemetryPingMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "p";
  u: number;
  r: number;
  a: number;
}

export interface PortListMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "pl";
  p: number[];
}

export interface DirectoryRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "dr";
  i: number;
  r: string;
  p: string;
  l: number;
  k?: string;
}

export type DirectoryEntryDirectory = ["d", string, number];
export type DirectoryEntryFile = ["f", string, number, number];
export type DirectoryEntry = DirectoryEntryDirectory | DirectoryEntryFile;

export interface DirectoryResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "ds";
  i: number;
  k?: string;
  e: DirectoryEntry[];
}

export interface StreamChunkMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "sc";
  x: string;
  q: number;
  e: 0 | 1;
  d: string;
}

export interface StreamAckMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "sa";
  x: string;
  q: number;
}

export interface StartSessionMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "si";
  i: number;
  s: string;
  p?: string;
  j?: SessionJitCredential;
}

export interface SessionJitCredential {
  t: string;
  e: number;
  s?: string;
  n?: string;
  r?: string;
  v?: Array<[string, string]>;
}

export interface JitKillSwitchRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "jk";
  i: number;
  s?: string;
  r?: string;
  x?: 0 | 1;
  m?: string;
}

export interface JitKillSwitchResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "jv";
  i: number;
  o: 0 | 1;
  a: number;
  m?: string;
}

export interface StartPromptMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "sp";
  i: number;
  x: string;
  s: string;
  p: string;
}

export interface TerminateSessionMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "st";
  i: number;
  s: string;
}

export interface SessionResultMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "sr";
  i: number;
  s: string;
  o: 0 | 1;
  m?: string;
  u?: string;
}

export interface SessionStatusRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "sq";
  i: number;
  p: string;
}

export interface SessionStatusResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "sv";
  i: number;
  o: 0 | 1;
  p?: number;
  d?: number;
  u?: string;
  m?: string;
}

export interface SessionLogRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "sl";
  i: number;
  x: string;
  l: number;
}

export type ProxyHeaderEntry = [string, string];

export interface PortProxyRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "pr";
  i: number;
  p: number;
  m: string;
  u: string;
  h: ProxyHeaderEntry[];
  b?: string;
}

export interface PortProxyResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "pv";
  i: number;
  o: 0 | 1;
  sc?: number;
  sm?: string;
  h?: ProxyHeaderEntry[];
  b?: string;
  m?: string;
}

export interface SetupStatusRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "cf";
  i: number;
}

export interface SetupStatusResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "cg";
  i: number;
  o: 0 | 1;
  c?: 0 | 1;
  u?: string;
  a?: 0 | 1;
  oc?: string;
  oh?: string;
  os?: number;
  op?: string;
  om?: string;
  rt?: number;
  m?: string;
}

export interface SetupSaveRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "cu";
  i: number;
  u: string;
  a: string;
  oc?: string;
  oh?: string;
  os?: number;
  op?: string;
  om?: string;
  rt?: number;
}

export interface SetupSaveResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "cv";
  i: number;
  k?: "setup";
  o: 0 | 1;
  m?: string;
}

export interface ConfigCheckPushRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "cc";
  i: number;
  k: "cfg";
  ph?: "session-init" | "runtime";
  sc?: "session-init" | "full";
  tid: string;
  tv: string;
  ts: number;
  ap: string;
  pd: string;
  alg?: string;
  sg?: string;
  pm?: "off" | "read-only" | "restricted";
  cfg: Record<string, unknown>;
}

export interface ConfigViewResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "cv";
  i: number;
  k: "cfg";
  ph?: "session-init" | "runtime";
  sc?: "session-init" | "full";
  o: 0 | 1;
  tid: string;
  tv: string;
  st: "applied" | "rejected";
  pd: string;
  at: number;
  ap?: string;
  vd?: string[];
  alg?: string;
  sg?: string;
  pm?: "off" | "read-only" | "restricted";
  m?: string;
}

export interface MkdirRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "md";
  i: number;
  r: string;
  p: string;
}

export interface MkdirResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "mr";
  i: number;
  o: 0 | 1;
  m?: string;
}

export interface RmdirRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "rd";
  i: number;
  r: string;
  p: string;
}

export interface RmdirResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "rr";
  i: number;
  o: 0 | 1;
  m?: string;
}

export interface RenameRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "rn";
  i: number;
  r: string;
  s: string;
  d: string;
}

export interface RenameResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "rp";
  i: number;
  o: 0 | 1;
  m?: string;
}

// Git Operations
export interface GitInitRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gi";
  i: number;
  r: string;
  p: string;
}

export interface GitInitResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gj";
  i: number;
  o: 0 | 1;
  m?: string;
}

export interface GitCloneRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gk";
  i: number;
  r: string;
  p: string;
  u: string;
  b?: string;
}

export interface GitCloneResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gl";
  i: number;
  o: 0 | 1;
  m?: string;
}

export interface GitStatusRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gs";
  i: number;
  r: string;
  p: string;
}

export interface GitStatusResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gt";
  i: number;
  o: 0 | 1;
  b?: string;
  a?: string[];
  m?: string[];
  u?: string[];
  d?: string[];
  c?: string;
  e?: string;
}

export interface GitAddRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "ga";
  i: number;
  r: string;
  p: string;
  f?: string;
  A?: 0 | 1;
}

export interface GitAddResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gb";
  i: number;
  o: 0 | 1;
  m?: string;
}

export interface GitCommitRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gp";
  i: number;
  r: string;
  p: string;
  m: string;
  a?: 0 | 1;
}

export interface GitCommitResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "go";
  i: number;
  o: 0 | 1;
  h?: string;
  m?: string;
}

export interface GitPushRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gh";
  i: number;
  r: string;
  p: string;
  o?: string;
  b?: string;
}

export interface GitPushResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gd";
  i: number;
  o: 0 | 1;
  m?: string;
}

export interface GitPullRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gm";
  i: number;
  r: string;
  p: string;
  o?: string;
  b?: string;
}

export interface GitPullResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gn";
  i: number;
  o: 0 | 1;
  m?: string;
}

export interface GitBranchRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gc";
  i: number;
  r: string;
  p: string;
  a?: "list" | "create" | "delete";
  n?: string;
}

export interface GitBranchResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gu";
  i: number;
  o: 0 | 1;
  b?: string[];
  c?: string;
  m?: string;
}

export interface GitCheckoutRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gx";
  i: number;
  r: string;
  p: string;
  b: string;
  c?: 0 | 1;
}

export interface GitCheckoutResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gy";
  i: number;
  o: 0 | 1;
  m?: string;
}

export interface GitConfigRequestMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gf";
  i: number;
  r: string;
  p: string;
  a: "get" | "set";
  n?: string;
  e?: string;
  g?: 0 | 1;
  cm?: 0 | 1;
}

export interface GitConfigResponseMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gv";
  i: number;
  o: 0 | 1;
  n?: string;
  e?: string;
  h?: string;
  a?: 0 | 1;
  m?: string;
}

export interface GitLogMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "gq";
  i: number;
  s: "meta" | "out" | "err";
  m: string;
}

export type ErrorCode = "AUTH" | "PROTO" | "PATH" | "ROOT" | "LIMIT" | "FLOW" | "INTERNAL" | "UPDATE_REQUIRED";

export interface ErrorMessage {
  v: typeof WS_PROTOCOL_VERSION;
  t: "e";
  i?: number;
  c: ErrorCode;
  m?: string;
}

export type WsMessage =
  | HandshakeInitMessage
  | HandshakeAckMessage
  | TelemetryPingMessage
  | PortListMessage
  | DirectoryRequestMessage
  | DirectoryResponseMessage
  | StreamChunkMessage
  | StreamAckMessage
  | StartSessionMessage
  | StartPromptMessage
  | TerminateSessionMessage
  | SessionResultMessage
  | SessionStatusRequestMessage
  | SessionStatusResponseMessage
  | SessionLogRequestMessage
  | PortProxyRequestMessage
  | PortProxyResponseMessage
  | SetupStatusRequestMessage
  | SetupStatusResponseMessage
  | SetupSaveRequestMessage
  | SetupSaveResponseMessage
  | ConfigCheckPushRequestMessage
  | ConfigViewResponseMessage
  | JitKillSwitchRequestMessage
  | JitKillSwitchResponseMessage
  | MkdirRequestMessage
  | MkdirResponseMessage
  | RmdirRequestMessage
  | RmdirResponseMessage
  | RenameRequestMessage
  | RenameResponseMessage
  | GitInitRequestMessage
  | GitInitResponseMessage
  | GitCloneRequestMessage
  | GitCloneResponseMessage
  | GitStatusRequestMessage
  | GitStatusResponseMessage
  | GitAddRequestMessage
  | GitAddResponseMessage
  | GitCommitRequestMessage
  | GitCommitResponseMessage
  | GitPushRequestMessage
  | GitPushResponseMessage
  | GitPullRequestMessage
  | GitPullResponseMessage
  | GitBranchRequestMessage
  | GitBranchResponseMessage
  | GitCheckoutRequestMessage
  | GitCheckoutResponseMessage
  | GitConfigRequestMessage
  | GitConfigResponseMessage
  | GitLogMessage
  | ErrorMessage;

export const MAX_STREAM_CHUNK_BYTES = 8192;
export const MAX_DIRECTORY_LIMIT = 256;
