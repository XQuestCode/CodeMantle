import { useState, useEffect, useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import {
  Settings,
  Folder,
  Monitor,
  Play,
  Square,
  RotateCw,
  Save,
  ArrowLeft,
  CheckCircle,
  AlertCircle,
  Loader2,
  Terminal,
  Globe,
  Key,
} from 'lucide-react'

interface SetupConfig {
  workspace_path: string
  control_plane_url: string
  auth_token: string
  start_on_boot: boolean
}

interface SettingsViewProps {
  config: SetupConfig
  setConfig: React.Dispatch<React.SetStateAction<SetupConfig>>
  onBackToWizard: () => void
}

type AgentStatus = 'stopped' | 'running' | 'starting' | 'stopping'
type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

export default function SettingsView({ config, setConfig, onBackToWizard }: SettingsViewProps) {
  const [agentStatus, setAgentStatus] = useState<AgentStatus>('stopped')
  const [autostartEnabled, setAutostartEnabled] = useState(config.start_on_boot)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveError, setSaveError] = useState('')
  const [logs, setLogs] = useState<string[]>([])
  const [dirty, setDirty] = useState(false)
  const [errors, setErrors] = useState<{ [key: string]: string }>({})

  // Track if config changed from saved version
  const [savedConfig, setSavedConfig] = useState<SetupConfig>(config)

  // Load autostart status on mount
  useEffect(() => {
    invoke<boolean>('check_autostart_status')
      .then(setAutostartEnabled)
      .catch(() => {})
  }, [])

  // Listen for agent events
  useEffect(() => {
    const unlistenLog = listen<string>('agent-log', (event) => {
      setLogs((prev) => [...prev.slice(-500), event.payload])
    })

    const unlistenStatus = listen<{ connected: boolean; first_time: boolean }>(
      'connection-status',
      (event) => {
        if (event.payload.connected) {
          setAgentStatus('running')
        }
      }
    )

    const unlistenStarted = listen<number>('agent-started', () => {
      setAgentStatus('running')
    })

    return () => {
      unlistenLog.then((f) => f())
      unlistenStatus.then((f) => f())
      unlistenStarted.then((f) => f())
    }
  }, [])

  const updateConfig = useCallback(
    (patch: Partial<SetupConfig>) => {
      setConfig((prev) => {
        const next = { ...prev, ...patch }
        setDirty(
          next.workspace_path !== savedConfig.workspace_path ||
            next.control_plane_url !== savedConfig.control_plane_url ||
            next.auth_token !== savedConfig.auth_token ||
            next.start_on_boot !== savedConfig.start_on_boot
        )
        return next
      })
    },
    [savedConfig, setConfig]
  )

  const validate = (): boolean => {
    const newErrors: { [key: string]: string } = {}

    if (!config.workspace_path) {
      newErrors.workspace_path = 'Workspace path is required'
    }

    if (!config.control_plane_url) {
      newErrors.control_plane_url = 'Control Plane URL is required'
    } else if (
      !config.control_plane_url.startsWith('wss://') &&
      !config.control_plane_url.startsWith('ws://')
    ) {
      newErrors.control_plane_url = 'URL must start with ws:// or wss://'
    }

    if (!config.auth_token) {
      newErrors.auth_token = 'Auth token is required'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSelectFolder = async () => {
    try {
      const folder = await invoke<string | null>('select_folder')
      if (folder) {
        updateConfig({ workspace_path: folder })
      }
    } catch (err) {
      console.error('Failed to select folder:', err)
    }
  }

  const handleToggleAutostart = async (enabled: boolean) => {
    setAutostartEnabled(enabled)
    updateConfig({ start_on_boot: enabled })

    try {
      await invoke('toggle_autostart', { enabled })
    } catch (err) {
      console.error('Failed to toggle autostart:', err)
      // Revert on failure
      setAutostartEnabled(!enabled)
      updateConfig({ start_on_boot: !enabled })
    }
  }

  const handleSave = async () => {
    if (!validate()) return

    setSaveStatus('saving')
    setSaveError('')

    try {
      await invoke('save_setup_config', { config })
      setSavedConfig({ ...config })
      setDirty(false)
      setSaveStatus('saved')
      setTimeout(() => setSaveStatus('idle'), 2000)
    } catch (err) {
      setSaveStatus('error')
      setSaveError(String(err))
    }
  }

  const handleStartAgent = async () => {
    if (!validate()) return

    // Save config first if dirty
    if (dirty) {
      try {
        await invoke('save_setup_config', { config })
        setSavedConfig({ ...config })
        setDirty(false)
      } catch (err) {
        setSaveError(`Failed to save config: ${err}`)
        return
      }
    }

    setAgentStatus('starting')
    setLogs([])

    try {
      await invoke('start_agent_daemon', { config })
    } catch (err) {
      setAgentStatus('stopped')
      setLogs((prev) => [...prev, `Error: ${err}`])
    }
  }

  const handleStopAgent = async () => {
    setAgentStatus('stopping')
    try {
      await invoke('stop_agent_daemon')
      setAgentStatus('stopped')
    } catch (err) {
      setAgentStatus('running')
      setLogs((prev) => [...prev, `Error stopping agent: ${err}`])
    }
  }

  const handleRestartAgent = async () => {
    setAgentStatus('stopping')
    setLogs([])

    try {
      await invoke('stop_agent_daemon')
    } catch {
      // Agent may not be running, that's fine
    }

    setAgentStatus('starting')

    try {
      await invoke('start_agent_daemon', { config })
    } catch (err) {
      setAgentStatus('stopped')
      setLogs((prev) => [...prev, `Error: ${err}`])
    }
  }

  return (
    <div className="settings-view">
      <div className="settings-header">
        <Settings size={32} className="step-icon" />
        <div>
          <h2>Settings</h2>
          <p className="settings-subtitle">Manage your CodeMantle agent configuration</p>
        </div>
      </div>

      {/* Service Control */}
      <section className="settings-section">
        <h3 className="section-title">
          <Terminal size={18} />
          Agent Service
        </h3>

        <div className="service-control">
          <div className="service-status">
            <span
              className={`status-dot ${agentStatus === 'running' ? 'status-running' : agentStatus === 'starting' || agentStatus === 'stopping' ? 'status-pending' : 'status-stopped'}`}
            />
            <span className="status-text">
              {agentStatus === 'running' && 'Agent running'}
              {agentStatus === 'stopped' && 'Agent stopped'}
              {agentStatus === 'starting' && 'Starting...'}
              {agentStatus === 'stopping' && 'Stopping...'}
            </span>
          </div>

          <div className="service-actions">
            {agentStatus === 'stopped' && (
              <button className="btn-primary btn-sm" onClick={handleStartAgent}>
                <Play size={16} />
                Start
              </button>
            )}
            {agentStatus === 'running' && (
              <>
                <button className="btn-secondary btn-sm" onClick={handleRestartAgent}>
                  <RotateCw size={16} />
                  Restart
                </button>
                <button className="btn-danger btn-sm" onClick={handleStopAgent}>
                  <Square size={16} />
                  Stop
                </button>
              </>
            )}
            {(agentStatus === 'starting' || agentStatus === 'stopping') && (
              <Loader2 className="spin" size={20} />
            )}
          </div>
        </div>
      </section>

      {/* Autostart */}
      <section className="settings-section">
        <h3 className="section-title">
          <Monitor size={18} />
          Startup
        </h3>

        <div className="autostart-toggle">
          <div className="toggle-info">
            <div>
              <label className="toggle-label">Launch CodeMantle on Startup</label>
              <p className="toggle-description">
                Automatically start the agent when you log in to your computer
              </p>
            </div>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={autostartEnabled}
              onChange={(e) => handleToggleAutostart(e.target.checked)}
            />
            <span className="slider"></span>
          </label>
        </div>
      </section>

      {/* Connection Config */}
      <section className="settings-section">
        <h3 className="section-title">
          <Globe size={18} />
          Connection
        </h3>

        <div className="settings-form-group">
          <label>Control Plane URL</label>
          <input
            type="text"
            value={config.control_plane_url}
            onChange={(e) => updateConfig({ control_plane_url: e.target.value })}
            placeholder="wss://codemantle.cloud/ws"
            className={errors.control_plane_url ? 'error' : ''}
          />
          {errors.control_plane_url && (
            <span className="field-error">{errors.control_plane_url}</span>
          )}
        </div>

        <div className="settings-form-group">
          <label>
            <Key size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
            Agent Auth Token
          </label>
          <input
            type="password"
            value={config.auth_token}
            onChange={(e) => updateConfig({ auth_token: e.target.value })}
            placeholder="Enter your auth token"
            className={errors.auth_token ? 'error' : ''}
          />
          {errors.auth_token && <span className="field-error">{errors.auth_token}</span>}
        </div>
      </section>

      {/* Workspace */}
      <section className="settings-section">
        <h3 className="section-title">
          <Folder size={18} />
          Workspace
        </h3>

        <div className="folder-picker">
          <div className="folder-display">
            <Folder size={20} />
            <span>{config.workspace_path || 'No folder selected'}</span>
          </div>
          <button className="btn-secondary btn-sm" onClick={handleSelectFolder}>
            Browse
          </button>
        </div>
        {errors.workspace_path && <span className="field-error">{errors.workspace_path}</span>}
      </section>

      {/* Agent Logs */}
      {logs.length > 0 && (
        <section className="settings-section">
          <h3 className="section-title">
            <Terminal size={18} />
            Agent Logs
          </h3>
          <div className="logs-scroll">
            {logs.map((log, i) => (
              <div key={i} className="log-line">
                {log}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Save bar */}
      <div className="settings-save-bar">
        <button className="btn-secondary btn-sm" onClick={onBackToWizard}>
          <ArrowLeft size={16} />
          Re-run Setup Wizard
        </button>

        <div className="save-group">
          {saveStatus === 'saved' && (
            <span className="save-confirmation">
              <CheckCircle size={16} />
              Saved
            </span>
          )}
          {saveStatus === 'error' && (
            <span className="save-error-inline">
              <AlertCircle size={16} />
              {saveError || 'Failed to save'}
            </span>
          )}
          <button
            className="btn-primary btn-sm"
            onClick={handleSave}
            disabled={!dirty || saveStatus === 'saving'}
          >
            {saveStatus === 'saving' ? (
              <Loader2 className="spin" size={16} />
            ) : (
              <Save size={16} />
            )}
            Save Changes
          </button>
        </div>
      </div>
    </div>
  )
}
