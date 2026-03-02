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

  return url;
}

/**
 * Validate a control-plane URL after normalization.
 * Returns an error message or undefined if valid.
 */
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
