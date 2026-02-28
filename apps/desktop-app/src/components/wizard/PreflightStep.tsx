import React, { useState, useEffect, useCallback, useRef } from 'react'
import { CheckCircle, ArrowRight, ArrowLeft, Monitor, Terminal, Loader2, AlertCircle } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import Button from '../ui/Button'
import Toggle from '../ui/Toggle'
import LogViewer from '../ui/LogViewer'
import Card from '../ui/Card'
import { useLogs } from '../../hooks/useLogs'
import { StepProps, ConnectionStatus } from '../../types'
import { truncateLogs } from '../../utils'

const PreflightStep = React.memo<StepProps>(({
  config,
  setConfig,
  onNext,
  onPrev,
}) => {
  const [status, setStatus] = useState<ConnectionStatus>('idle')
  const [autostartEnabled, setAutostartEnabled] = useState(config.start_on_boot)
  const { logs, addLog, clearLogs } = useLogs({ maxSize: 500 })
  const unlistenRef = useRef<(() => void) | null>(null)
  const unlistenStatusRef = useRef<(() => void) | null>(null)

  // Setup event listeners
  useEffect(() => {
    const setupListeners = async () => {
      // Listen for agent logs
      const unlisten = await listen<string>('agent-log', (event) => {
        addLog(event.payload)
      })
      unlistenRef.current = unlisten

      // Listen for connection status
      const unlistenStatus = await listen<{connected: boolean; first_time: boolean}>('connection-status', (event) => {
        if (event.payload.connected) {
          setStatus('ready')
        }
      })
      unlistenStatusRef.current = unlistenStatus
    }

    setupListeners()

    return () => {
      unlistenRef.current?.()
      unlistenStatusRef.current?.()
    }
  }, [addLog])

  const handleStartAgent = useCallback(async () => {
    setStatus('checking')
    clearLogs()
    
    try {
      await invoke('start_agent_daemon', { config })
    } catch (err) {
      setStatus('error')
      addLog(`Error: ${err}`)
    }
  }, [config, clearLogs, addLog])

  const handleToggleAutostart = useCallback(async (enabled: boolean) => {
    setAutostartEnabled(enabled)
    setConfig(prev => ({ ...prev, start_on_boot: enabled }))
    
    try {
      await invoke('toggle_autostart', { enabled })
    } catch (err) {
      console.error('Failed to toggle autostart:', err)
    }
  }, [setConfig])

  const handleFinish = useCallback(async () => {
    try {
      await invoke('save_setup_config', { config })
      onNext()
    } catch (err) {
      console.error('Failed to save config:', err)
    }
  }, [config, onNext])

  const getStatusConfig = () => {
    switch (status) {
      case 'idle':
        return {
          icon: <Terminal size={20} />,
          text: 'Start Agent & Test Connection',
          color: 'primary',
        }
      case 'checking':
        return {
          icon: <Loader2 size={20} className="animate-spin" />,
          text: 'Starting agent and testing connection...',
          color: 'primary',
        }
      case 'ready':
        return {
          icon: <CheckCircle size={20} />,
          text: 'Agent connected successfully!',
          color: 'success',
        }
      case 'error':
        return {
          icon: <AlertCircle size={20} />,
          text: 'Connection failed. Check the logs.',
          color: 'error',
        }
    }
  }

  const statusConfig = getStatusConfig()

  return (
    <motion.div
      className="step-content"
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      transition={{ duration: 0.3 }}
    >
      <div className="step-header">
        <motion.div
          className="step-icon-wrapper"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: 'spring', stiffness: 200, delay: 0.1 }}
        >
          <CheckCircle size={32} />
        </motion.div>
        <h2 className="step-title">Pre-flight Check</h2>
        <p className="step-description">
          Verify the agent can connect successfully
        </p>
      </div>

      <Card className="autostart-card" hover={false}>
        <Toggle
          checked={autostartEnabled}
          onChange={handleToggleAutostart}
          icon={<Monitor size={24} />}
          label="Launch CodeMantle on Startup"
          description="Automatically start the agent when you log in"
        />
        
        <AnimatePresence>
          {autostartEnabled && (
            <motion.div
              className="autostart-note"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <CheckCircle size={16} />
              <span>CodeMantle will register with OS startup after first connection</span>
            </motion.div>
          )}
        </AnimatePresence>
      </Card>

      <div className="preflight-status">
        <AnimatePresence mode="wait">
          {status === 'idle' && (
            <motion.div
              key="idle"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <Button
                variant="primary"
                size="lg"
                onClick={handleStartAgent}
                leftIcon={statusConfig.icon}
                className="btn-full-width"
              >
                {statusConfig.text}
              </Button>
            </motion.div>
          )}

          {status === 'checking' && (
            <motion.div
              key="checking"
              className="status-message status-checking"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              {statusConfig.icon}
              <span>{statusConfig.text}</span>
            </motion.div>
          )}

          {status === 'ready' && (
            <motion.div
              key="ready"
              className="status-message status-ready"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
            >
              {statusConfig.icon}
              <span>{statusConfig.text}</span>
            </motion.div>
          )}

          {status === 'error' && (
            <motion.div
              key="error"
              className="status-message status-error"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              {statusConfig.icon}
              <span>{statusConfig.text}</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <LogViewer logs={logs} maxHeight={200} />

      <div className="step-actions">
        <Button
          variant="ghost"
          onClick={onPrev}
          disabled={status === 'checking'}
          leftIcon={<ArrowLeft size={18} />}
        >
          Back
        </Button>
        <Button
          variant="primary"
          onClick={handleFinish}
          disabled={status !== 'ready'}
          rightIcon={<ArrowRight size={18} />}
        >
          Complete Setup
        </Button>
      </div>
    </motion.div>
  )
})

PreflightStep.displayName = 'PreflightStep'

export default PreflightStep
