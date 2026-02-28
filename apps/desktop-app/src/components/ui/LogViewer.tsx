import React, { useMemo } from 'react'
import { FixedSizeList as List, ListChildComponentProps } from 'react-window'
import AutoSizer from 'react-virtualized-auto-sizer'
import { motion } from 'framer-motion'
import { formatTimestamp, generateId } from '../../utils'
import { LogEntry } from '../../types'

interface LogViewerProps {
  logs: string[]
  maxHeight?: number
  className?: string
}

// Create log entries with IDs for virtualization
const createLogEntries = (logs: string[]): LogEntry[] => {
  return logs.map((message, index) => ({
    id: generateId(),
    timestamp: Date.now() - (logs.length - index) * 1000,
    message,
    type: message.includes('[stderr]') ? 'stderr' : 'stdout',
  }))
}

// Individual log row component
const LogRow = React.memo<ListChildComponentProps<LogEntry[]>>(({
  index,
  style,
  data,
}: ListChildComponentProps<LogEntry[]>) => {
  const entry = data[index]
  
  return (
    <motion.div
      style={style}
      className={`log-row log-row-${entry.type}`}
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.15, delay: index * 0.01 }}
    >
      <span className="log-timestamp">{formatTimestamp(entry.timestamp)}</span>
      <span className="log-message">{entry.message}</span>
    </motion.div>
  )
})

LogRow.displayName = 'LogRow'

const LogViewer = React.memo<LogViewerProps>(({
  logs,
  maxHeight = 240,
  className,
}) => {
  const logEntries = useMemo(() => createLogEntries(logs), [logs])
  
  // Scroll to bottom when new logs arrive
  const listRef = React.useRef<List>(null)
  
  React.useEffect(() => {
    if (listRef.current && logs.length > 0) {
      listRef.current.scrollToItem(logs.length - 1, 'end')
    }
  }, [logs.length])

  if (logs.length === 0) {
    return null
  }

  return (
    <motion.div
      className={`log-viewer ${className || ''}`}
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="log-header">
        <span className="log-title">Agent Logs</span>
        <span className="log-count">{logs.length} entries</span>
      </div>
      
      <div className="log-container" style={{ maxHeight }}>
        <AutoSizer>
          {({ height, width }: { height: number; width: number }) => (
            <List
              ref={listRef}
              height={Math.min(height, maxHeight)}
              width={width}
              itemCount={logEntries.length}
              itemSize={28}
              itemData={logEntries}
              className="log-list"
            >
              {LogRow}
            </List>
          )}
        </AutoSizer>
      </div>
    </motion.div>
  )
})

LogViewer.displayName = 'LogViewer'

export default LogViewer
