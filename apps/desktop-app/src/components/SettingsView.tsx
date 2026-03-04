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
  Info,
  Eye,
  EyeOff,
} from 'lucide-react'
import { normalizeControlPlaneUrl, validateControlPlaneUrl, isFilesystemRoot } from '../utils'

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
  const [showToken, setShowToken] = useState(false)
  const [showTokenHelp, setShowTokenHelp] = useState(false)

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
        } else {
          setAgentStatus('stopped')
          setLogs((prev) => [...prev.slice(-500), '[system] Connection failed: agent could not establish WebSocket handshake within 15 seconds.'])
        }
      }
    )

    const unlistenStarted = listen<number>('agent-started', () => {
      setAgentStatus('starting')
    })

    // Listen for agent exit (crash / unexpected termination)
    const unlistenExit = listen<number>('agent-exit', () => {
      setAgentStatus('stopped')
      setLogs((prev) => [...prev.slice(-500), '[system] Agent process has stopped'])
    })

    return () => {
      unlistenLog.then((f) => f())
      unlistenStatus.then((f) => f())
      unlistenStarted.then((f) => f())
      unlistenExit.then((f) => f())
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
    } else if (isFilesystemRoot(config.workspace_path)) {
      newErrors.workspace_path = 'Cannot use a drive root as workspace. Please select a subfolder.'
    }

    const urlError = validateControlPlaneUrl(config.control_plane_url)
    if (urlError) newErrors.control_plane_url = urlError

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
        setErrors((prev) => {
          const next = { ...prev }
          delete next.workspace_path
          return next
        })
      }
    } catch (err) {
      setErrors((prev) => ({ ...prev, workspace_path: String(err) }))
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
    // Build normalized config to avoid stale-state issues with setConfig
    const normalizedConfig: typeof config = {
      ...config,
      control_plane_url: config.control_plane_url
        ? normalizeControlPlaneUrl(config.control_plane_url)
        : config.control_plane_url,
    }

    if (normalizedConfig.control_plane_url !== config.control_plane_url) {
      setConfig(normalizedConfig)
    }

    if (!validate()) return

    setSaveStatus('saving')
    setSaveError('')

    try {
      await invoke('save_setup_config', { config: normalizedConfig })
      setSavedConfig({ ...normalizedConfig })
      setDirty(false)
      setSaveStatus('saved')
      setTimeout(() => setSaveStatus('idle'), 2000)
    } catch (err) {
      setSaveStatus('error')
      setSaveError(String(err))
    }
  }

  const handleStartAgent = async () => {
    // Build normalized config to avoid stale-state issues with setConfig
    const normalizedConfig: typeof config = {
      ...config,
      control_plane_url: config.control_plane_url
        ? normalizeControlPlaneUrl(config.control_plane_url)
        : config.control_plane_url,
    }

    if (normalizedConfig.control_plane_url !== config.control_plane_url) {
      setConfig(normalizedConfig)
    }

    if (!validate()) return

    // Save config first if dirty
    if (dirty) {
      try {
        await invoke('save_setup_config', { config: normalizedConfig })
        setSavedConfig({ ...normalizedConfig })
        setDirty(false)
      } catch (err) {
        setSaveError(`Failed to save config: ${err}`)
        return
      }
    }

    setAgentStatus('starting')
    setLogs([])

    try {
      await invoke('start_agent_daemon', { config: normalizedConfig })
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

    // Build normalized config to avoid stale-state issues
    const normalizedConfig: typeof config = {
      ...config,
      control_plane_url: config.control_plane_url
        ? normalizeControlPlaneUrl(config.control_plane_url)
        : config.control_plane_url,
    }

    setAgentStatus('starting')

    try {
      await invoke('start_agent_daemon', { config: normalizedConfig })
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
          <label>Control Plane Server</label>
          <input
            type="text"
            value={config.control_plane_url}
            onChange={(e) => updateConfig({ control_plane_url: e.target.value })}
            placeholder="codemantle.cloud"
            className={errors.control_plane_url ? 'error' : ''}
          />
          <span className="field-helper">Enter your server domain (e.g. myserver.com). Protocol and /ws path are added automatically.</span>
          {errors.control_plane_url && (
            <span className="field-error">{errors.control_plane_url}</span>
          )}
        </div>

        <div className="settings-form-group">
          <label>
            <Key size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
            Agent Auth Token
          </label>
          <div className="input-with-action">
            <input
              type={showToken ? 'text' : 'password'}
              value={config.auth_token}
              onChange={(e) => updateConfig({ auth_token: e.target.value })}
              placeholder="Enter your VALID_TOKENS value"
              className={errors.auth_token ? 'error' : ''}
            />
            <button
              type="button"
              className="input-action-btn"
              onClick={() => setShowToken(!showToken)}
              title={showToken ? 'Hide token' : 'Show token'}
            >
              {showToken ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>
          {errors.auth_token && <span className="field-error">{errors.auth_token}</span>}

          <button
            type="button"
            className="token-help-toggle"
            onClick={() => setShowTokenHelp(!showTokenHelp)}
          >
            <Info size={14} />
            {showTokenHelp ? 'Hide instructions' : 'Where do I find this token?'}
          </button>

          {showTokenHelp && (
            <div className="token-help-box">
              <h4>How to retrieve your Auth Token</h4>
              <p>
                This token must match a value in the <code>VALID_TOKENS</code> environment
                variable on your control-plane server.
              </p>
              <ol>
                <li>
                  <strong>Check your control-plane <code>.env</code> file</strong> for the
                  <code> VALID_TOKENS</code> variable.
                </li>
                <li>
                  <strong>If you ran <code>bootstrap init</code></strong>, a token was
                  auto-generated. Look for <code>VALID_TOKENS=...</code> in the output.
                </li>
                <li>
                  <strong>To generate a new token</strong>, create a random string (32+ chars)
                  and add it to <code>VALID_TOKENS</code> on the server, then restart.
                </li>
              </ol>
              <p className="token-help-note">
                After editing, save changes and restart the agent for the new token to take effect.
              </p>
            </div>
          )}
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
