import { useCallback, useRef, useState } from 'react'

interface UseLogsOptions {
  maxSize?: number
}

export function useLogs(options: UseLogsOptions = {}) {
  const { maxSize = 500 } = options
  const [logs, setLogs] = useState<string[]>([])
  const logsRef = useRef<string[]>([])

  const addLog = useCallback((message: string) => {
    logsRef.current = [...logsRef.current, message]
    
    // Truncate if exceeding max size
    if (logsRef.current.length > maxSize) {
      logsRef.current = logsRef.current.slice(logsRef.current.length - maxSize)
    }
    
    setLogs(logsRef.current)
  }, [maxSize])

  const clearLogs = useCallback(() => {
    logsRef.current = []
    setLogs([])
  }, [])

  const resetLogs = useCallback(() => {
    logsRef.current = []
    setLogs([])
  }, [])

  return {
    logs,
    addLog,
    clearLogs,
    resetLogs,
  }
}
