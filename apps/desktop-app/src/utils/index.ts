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
