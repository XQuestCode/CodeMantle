import { useCallback, useRef } from 'react'

export function useStableCallback<T extends (...args: any[]) => any>(callback: T): T {
  const callbackRef = useRef(callback)
  callbackRef.current = callback
  
  return useCallback((...args: any[]) => {
    return callbackRef.current(...args)
  }, []) as T
}

export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
}

export function truncateLogs<T>(logs: T[], maxSize: number = 500): T[] {
  if (logs.length <= maxSize) return logs
  return logs.slice(logs.length - maxSize)
}

export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/**
 * Normalize a user-provided control plane URL into a full WebSocket URL.
 *
 * Accepts bare domains (e.g. "codemantle.xquest.dev"), domains with ports,
 * or full ws:// / wss:// URLs.  Returns the URL unchanged if it already
 * starts with ws:// or wss://.
 *
 * When the URL has no explicit path (or just "/"), we auto-append "/ws"
 * because production and self-hosted deployments use Nginx to route the
 * /ws location to the agent WebSocket server on port 8787.
 *
 * Exception: localhost / 127.0.0.1 URLs with an explicit port are left
 * untouched (dev mode connects directly to port 8787 without a path).
 */
export function normalizeControlPlaneUrl(input: string): string {
  let url = input.trim();
  if (!url) return url;

  // Strip accidental http(s):// — user likely copy-pasted a browser URL
  if (url.startsWith("https://")) {
    url = "wss://" + url.slice("https://".length);
  } else if (url.startsWith("http://")) {
    url = "ws://" + url.slice("http://".length);
  }

  // If no protocol at all, default to wss://
  if (!url.startsWith("wss://") && !url.startsWith("ws://")) {
    url = "wss://" + url;
  }

  // Remove trailing slashes for consistency
  url = url.replace(/\/+$/, "");

  // Auto-append /ws for non-localhost URLs that have no explicit path.
  // Localhost/127.0.0.1 with a port is assumed to be a dev setup connecting
  // directly to the control plane WebSocket server.
  try {
    const parsed = new URL(url.replace(/^ws/, "http")); // URL() needs http(s) scheme
    const isLocal =
      parsed.hostname === "localhost" ||
      parsed.hostname === "127.0.0.1" ||
      parsed.hostname === "::1";
    const hasPath = parsed.pathname !== "/" && parsed.pathname !== "";
    if (!hasPath && !isLocal) {
      url = url + "/ws";
    }
  } catch {
    // If URL parsing fails, leave it as-is — validateControlPlaneUrl will catch it
  }

  return url;
}

/**
 * Validate a control-plane URL after normalization.
 * Returns an error message or undefined if valid.
 */
/**
 * Returns true if the given path is a filesystem root (e.g. "C:\", "E:\", "/").
 * Used on the frontend as an early guard before invoking Rust commands.
 */
export function isFilesystemRoot(path: string): boolean {
  const trimmed = path.trim();
  // Unix root
  if (trimmed === "/") return true;
  // Windows drive root: "C:", "C:\", "C:/"
  if (/^[a-zA-Z]:[/\\]*$/.test(trimmed)) return true;
  return false;
}

export function validateControlPlaneUrl(value: string): string | undefined {
  if (!value) return "Control plane server is required";
  const normalized = normalizeControlPlaneUrl(value);
  try {
    const parsed = new URL(normalized);
    if (parsed.protocol !== "wss:" && parsed.protocol !== "ws:") {
      return "Invalid protocol — expected ws:// or wss://";
    }
    if (!parsed.hostname) {
      return "A hostname is required";
    }
  } catch {
    return "Invalid URL format";
  }
  return undefined;
}
