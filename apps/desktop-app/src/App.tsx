import { useState, useEffect, useRef } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { Folder, Settings, CheckCircle, Loader2, Terminal, ArrowRight, ArrowLeft, Monitor, Info, Eye, EyeOff, Square, AlertCircle } from 'lucide-react'
import './App.css'
import { useAutoUpdater } from './updater'
import Logo from './components/ui/Logo'
import SettingsView from './components/SettingsView'
import { normalizeControlPlaneUrl, validateControlPlaneUrl, isFilesystemRoot } from './utils'

interface SetupConfig {
  workspace_path: string
  control_plane_url: string
  auth_token: string
  start_on_boot: boolean
}

interface StepProps {
  config: SetupConfig
  setConfig: React.Dispatch<React.SetStateAction<SetupConfig>>
  onNext: () => void
  onPrev?: () => void
  isLoading?: boolean
}

type AppView = 'wizard' | 'settings'

interface DependencyInfo {
  name: string
  installed: boolean
  version: string | null
  path: string | null
  error: string | null
}

interface InstallProgress {
  dependency: string
  stage: string
  message: string
  done: boolean
  success: boolean
}

// Step 1: Workspace Folder Picker
function WorkspaceStep({ config, setConfig, onNext, isLoading }: StepProps) {
  const [error, setError] = useState('')

  const handleSelectFolder = async () => {
    try {
      const folder = await invoke<string | null>('select_folder')
      if (folder) {
        setConfig(prev => ({ ...prev, workspace_path: folder }))
        setError('')
      }
    } catch (err) {
      setError(err as string)
    }
  }

  const handleNext = () => {
    if (config.workspace_path && isFilesystemRoot(config.workspace_path)) {
      setError('Cannot use a drive root as workspace. Please select a subfolder.')
      return
    }
    onNext()
  }

  return (
    <div className="step-container">
      <div className="step-header">
        <Folder size={48} className="step-icon" />
        <h2>Choose Workspace</h2>
        <p>Select the folder where your projects will be stored</p>
      </div>

      <div className="folder-picker">
        <div className="folder-display">
          <Folder size={20} />
          <span>{config.workspace_path || 'No folder selected'}</span>
        </div>
        <button 
          className="btn-secondary" 
          onClick={handleSelectFolder}
          disabled={isLoading}
        >
          Browse
        </button>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="step-actions">
        <button 
          className="btn-primary" 
          onClick={handleNext}
          disabled={!config.workspace_path || isLoading}
        >
          {isLoading ? <Loader2 className="spin" size={20} /> : <ArrowRight size={20} />}
          Next
        </button>
      </div>
    </div>
  )
}

// Step 2: Connection Settings
function ConnectionStep({ config, setConfig, onNext, onPrev }: StepProps) {
  const [errors, setErrors] = useState<{[key: string]: string}>({})
  const [showToken, setShowToken] = useState(false)
  const [showTokenHelp, setShowTokenHelp] = useState(false)

  const validate = () => {
    const newErrors: {[key: string]: string} = {}
    
    const urlError = validateControlPlaneUrl(config.control_plane_url)
    if (urlError) newErrors.control_plane_url = urlError
    
    if (!config.auth_token) {
      newErrors.auth_token = 'Auth token is required'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleNext = () => {
    // Normalize the URL before validation
    if (config.control_plane_url) {
      const normalized = normalizeControlPlaneUrl(config.control_plane_url)
      if (normalized !== config.control_plane_url) {
        setConfig(prev => ({ ...prev, control_plane_url: normalized }))
      }
    }
    if (validate()) {
      onNext()
    }
  }

  return (
    <div className="step-container">
      <div className="step-header">
        <Settings size={48} className="step-icon" />
        <h2>Connection Settings</h2>
        <p>Configure how CodeMantle connects to the cloud</p>
      </div>

      <div className="form-group">
        <label>Control Plane Server</label>
        <input
          type="text"
          value={config.control_plane_url}
          onChange={(e) => setConfig(prev => ({ ...prev, control_plane_url: e.target.value }))}
          placeholder="codemantle.cloud"
          className={errors.control_plane_url ? 'error' : ''}
        />
        <span className="field-helper">Enter your server domain (e.g. myserver.com). Protocol and /ws path are added automatically.</span>
        {errors.control_plane_url && <span className="field-error">{errors.control_plane_url}</span>}
      </div>

      <div className="form-group">
        <label>Agent Auth Token</label>
        <div className="input-with-action">
          <input
            type={showToken ? 'text' : 'password'}
            value={config.auth_token}
            onChange={(e) => setConfig(prev => ({ ...prev, auth_token: e.target.value }))}
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
              variable on your control-plane server. Here is how to find or set it:
            </p>
            <ol>
              <li>
                <strong>Check your control-plane <code>.env</code> file</strong> for the
                <code>VALID_TOKENS</code> variable. It contains one or more comma-separated tokens.
              </li>
              <li>
                <strong>If you ran <code>bootstrap init</code></strong>, a token was auto-generated.
                Look for <code>VALID_TOKENS=...</code> in the output or your <code>.env</code> file.
              </li>
              <li>
                <strong>To generate a new token</strong>, create a random string (e.g. 32+ characters)
                and add it to <code>VALID_TOKENS</code> on the server. Then restart the control plane.
              </li>
              <li>
                <strong>Copy that exact token value</strong> and paste it above. The agent uses this
                to authenticate its WebSocket handshake with the control plane.
              </li>
            </ol>
            <p className="token-help-note">
              Multiple agents can share the same token, or each can have a unique one
              (comma-separated in <code>VALID_TOKENS</code>).
            </p>
          </div>
        )}
      </div>

      <div className="step-actions">
        <button className="btn-secondary" onClick={onPrev}>
          <ArrowLeft size={20} />
          Back
        </button>
        <button className="btn-primary" onClick={handleNext}>
          Next
          <ArrowRight size={20} />
        </button>
      </div>
    </div>
  )
}

// Step 3: Pre-flight Status with Autostart Toggle
function PreflightStep({ config, setConfig, onNext, onPrev, onAgentConnected }: StepProps & { onAgentConnected: () => void }) {
  const [status, setStatus] = useState<'idle' | 'checking-deps' | 'deps-missing' | 'installing-dep' | 'checking' | 'ready' | 'error'>('idle')
  const [logs, setLogs] = useState<string[]>([])
  const [autostartEnabled, setAutostartEnabled] = useState(config.start_on_boot)
  const [deps, setDeps] = useState<DependencyInfo[]>([])
  const [installProgress, setInstallProgress] = useState<InstallProgress | null>(null)
  const hasConnected = useRef(false)

  useEffect(() => {
    // Listen for agent logs
    const unlisten = listen<string>('agent-log', (event) => {
      setLogs(prev => [...prev, event.payload])
    })

    // Listen for connection status
    const unlistenStatus = listen<{connected: boolean; first_time: boolean}>('connection-status', (event) => {
      if (event.payload.connected) {
        hasConnected.current = true
        onAgentConnected()
        setStatus('ready')
      } else {
        setStatus('error')
        setLogs(prev => [...prev, 'Connection failed: agent could not establish WebSocket handshake within 15 seconds.'])
      }
    })

    // Listen for agent exit (crash / unexpected termination)
    const unlistenExit = listen<number>('agent-exit', (event) => {
      setStatus('error')
      setLogs(prev => [...prev, `Agent process exited with code ${event.payload}`])
    })

    const unlistenProgress = listen<InstallProgress>('dependency-install-progress', (event) => {
      setInstallProgress(event.payload)
      if (event.payload.message) {
        setLogs(prev => [...prev, `[${event.payload.dependency}] ${event.payload.message}`])
      }
    })

    return () => {
      unlisten.then(f => f())
      unlistenStatus.then(f => f())
      unlistenExit.then(f => f())
      unlistenProgress.then(f => f())
    }
  }, [])

  const checkDependencies = async () => {
    setStatus('checking-deps')
    setLogs([])
    try {
      const results = await invoke<DependencyInfo[]>('check_dependencies')
      setDeps(results)
      const missing = results.filter(d => !d.installed)
      if (missing.length > 0) {
        setStatus('deps-missing')
      } else {
        // All deps found, proceed to start agent
        setStatus('checking')
        try {
          await invoke('start_agent_daemon', { config })
        } catch (err) {
          setStatus('error')
          setLogs(prev => [...prev, `Error: ${err}`])
        }
      }
    } catch (err) {
      setStatus('error')
      setLogs(prev => [...prev, `Failed to check dependencies: ${err}`])
    }
  }

  const installDependency = async (name: string) => {
    setStatus('installing-dep')
    setInstallProgress({ dependency: name, stage: 'starting', message: `Installing ${name}...`, done: false, success: false })
    try {
      await invoke('install_dependency', { name })
      // Re-check all dependencies after install
      const results = await invoke<DependencyInfo[]>('check_dependencies')
      setDeps(results)
      const stillMissing = results.filter(d => !d.installed)
      if (stillMissing.length > 0) {
        setStatus('deps-missing')
      } else {
        setStatus('checking')
        try {
          await invoke('start_agent_daemon', { config })
        } catch (err) {
          setStatus('error')
          setLogs(prev => [...prev, `Error: ${err}`])
        }
      }
      setInstallProgress(null)
    } catch (err) {
      setInstallProgress(null)
      setStatus('deps-missing')
      setLogs(prev => [...prev, `Failed to install ${name}: ${err}`])
    }
  }

  const handleStartAgent = async () => {
    await checkDependencies()
  }

  const handleStopAgent = async () => {
    try {
      await invoke('stop_agent_daemon')
      setStatus('idle')
      setLogs(prev => [...prev, 'Agent stopped.'])
    } catch (err) {
      setLogs(prev => [...prev, `Error stopping agent: ${err}`])
    }
  }

  const handleToggleAutostart = async (enabled: boolean) => {
    setAutostartEnabled(enabled)
    setConfig(prev => ({ ...prev, start_on_boot: enabled }))
    
    try {
      await invoke('toggle_autostart', { enabled })
    } catch (err) {
      console.error('Failed to toggle autostart:', err)
    }
  }

  const handleFinish = async () => {
    try {
      await invoke('save_setup_config', { config })
      onNext()
    } catch (err) {
      setLogs(prev => [...prev, `Error saving setup: ${err}`])
      setStatus('error')
      console.error('Failed to save config:', err)
    }
  }

  return (
    <div className="step-container">
      <div className="step-header">
        <CheckCircle size={48} className="step-icon" />
        <h2>Pre-flight Check</h2>
        <p>Verify the agent can connect successfully</p>
      </div>

      {/* Autostart Toggle */}
      <div className="autostart-toggle-container">
        <div className="autostart-toggle">
          <div className="toggle-info">
            <Monitor size={24} />
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
        {autostartEnabled && (
          <div className="autostart-note">
            <CheckCircle size={16} />
            <span>CodeMantle will register with the OS startup registry after first successful connection</span>
          </div>
        )}
      </div>

      {/* Connection Test */}
      <div className="preflight-actions">
        {status === 'checking-deps' && (
          <div className="checking-status">
            <Loader2 className="spin" size={24} />
            <span>Checking dependencies...</span>
          </div>
        )}

        {status === 'deps-missing' && (
          <div className="deps-missing-container">
            <div className="deps-status-header">
              <AlertCircle size={20} className="error-icon" />
              <span>Missing dependencies detected</span>
            </div>
            <div className="deps-list">
              {deps.map(dep => (
                <div key={dep.name} className={`dep-item ${dep.installed ? 'dep-installed' : 'dep-missing'}`}>
                  <div className="dep-info">
                    {dep.installed ? <CheckCircle size={16} className="success-icon" /> : <AlertCircle size={16} className="error-icon" />}
                    <span className="dep-name">{dep.name}</span>
                    {dep.installed && dep.version && <span className="dep-version">v{dep.version}</span>}
                  </div>
                  {!dep.installed && (
                    <button
                      className="btn-primary btn-sm"
                      onClick={() => installDependency(dep.name)}
                      disabled={false}
                    >
                      Install
                    </button>
                  )}
                </div>
              ))}
            </div>
            {deps.every(d => d.installed) && (
              <button className="btn-primary" onClick={() => checkDependencies()}>
                Continue
              </button>
            )}
          </div>
        )}

        {status === 'installing-dep' && installProgress && (
          <div className="checking-status">
            <Loader2 className="spin" size={24} />
            <span>Installing {installProgress.dependency}... {installProgress.message}</span>
          </div>
        )}

        {status === 'idle' && (
          <button className="btn-primary btn-large" onClick={handleStartAgent}>
            <Terminal size={20} />
            Start Agent & Test Connection
          </button>
        )}
        
        {status === 'checking' && (
          <div className="checking-status">
            <Loader2 className="spin" size={24} />
            <span>Starting agent and testing connection...</span>
            <button className="btn-ghost btn-sm" onClick={handleStopAgent} style={{ marginLeft: 'auto' }}>
              <Square size={14} />
              Stop
            </button>
          </div>
        )}

        {status === 'ready' && (
          <div className="ready-status">
            <CheckCircle size={24} className="success-icon" />
            <span>Agent connected successfully!</span>
            <button className="btn-ghost btn-sm" onClick={handleStopAgent} style={{ marginLeft: 'auto' }}>
              <Square size={14} />
              Stop
            </button>
          </div>
        )}

        {status === 'ready' && (
          <div className="connection-summary">
            <h4>Connection Details</h4>
            <div className="connection-summary-row">
              <span className="connection-summary-label">Server</span>
              <span className="connection-summary-value">{config.control_plane_url}</span>
            </div>
            <div className="connection-summary-row">
              <span className="connection-summary-label">Auth Token</span>
              <span className="connection-summary-value">
                {config.auth_token.length > 8
                  ? config.auth_token.slice(0, 4) + '****' + config.auth_token.slice(-4)
                  : '****'}
              </span>
            </div>
            <p className="connection-summary-note">
              <Info size={14} />
              This token matches a <code>VALID_TOKENS</code> entry on your control plane.
              You can update it later in Settings.
            </p>
          </div>
        )}

        {status === 'error' && (
          <div className="error-status">
            <span className="error-text">Connection failed. Check the logs below.</span>
          </div>
        )}
      </div>

      {/* Logs */}
      {logs.length > 0 && (
        <div className="logs-container">
          <h4>Agent Logs</h4>
          <div className="logs-scroll">
            {logs.map((log, i) => (
              <div key={i} className="log-line">{log}</div>
            ))}
          </div>
        </div>
      )}

      <div className="step-actions">
        {!hasConnected.current && (
          <button
            className="btn-secondary"
            onClick={onPrev}
            disabled={status === 'checking'}
          >
            <ArrowLeft size={20} />
            Back
          </button>
        )}
        <button 
          className="btn-primary" 
          onClick={handleFinish}
          disabled={status !== 'ready'}
        >
          Finish Setup
          <CheckCircle size={20} />
        </button>
      </div>
    </div>
  )
}

// Success Screen — now transitions to Settings after brief display
function SuccessScreen({ onGoToSettings }: { onGoToSettings: () => void }) {
  useEffect(() => {
    const timer = setTimeout(() => {
      onGoToSettings()
    }, 3000)
    return () => clearTimeout(timer)
  }, [onGoToSettings])

  return (
    <div className="step-container success">
      <div className="success-icon-large">
        <Logo size="xl" showText={false} animated={true} />
      </div>
      <h2>Setup Complete!</h2>
      <p>CodeMantle is now running and ready to use.</p>
      <p className="sub-text">
        The agent will minimize to the system tray. Click the tray icon to show/hide the window.
      </p>
      <p className="sub-text" style={{ marginTop: 8, fontSize: 13, opacity: 0.7 }}>
        Redirecting to settings...
      </p>
    </div>
  )
}

function App() {
  const updater = useAutoUpdater()
  const [view, setView] = useState<AppView>('wizard')
  const [currentStep, setCurrentStep] = useState(1)
  const [configLoaded, setConfigLoaded] = useState(false)
  const [agentConnected, setAgentConnected] = useState(false)
  const [config, setConfig] = useState<SetupConfig>({
    workspace_path: '',
    control_plane_url: 'codemantle.cloud',
    auth_token: '',
    start_on_boot: false,
  })

  // On mount: load saved config. If exists, go straight to settings.
  useEffect(() => {
    invoke<SetupConfig | null>('load_setup_config')
      .then((saved) => {
        if (saved) {
          setConfig(saved)
          setView('settings')
        }
        setConfigLoaded(true)
      })
      .catch(() => {
        setConfigLoaded(true)
      })
  }, [])

  // Listen for tray "settings" event
  useEffect(() => {
    const unlisten = listen('open-settings', () => {
      setView('settings')
    })
    return () => { unlisten.then(f => f()) }
  }, [])

  const handleWizardComplete = () => {
    // Step 4 success screen, then auto-transition to settings
    setCurrentStep(4)
  }

  const handleGoToSettings = () => {
    setView('settings')
    setCurrentStep(1) // reset wizard for potential re-run
  }

  const handleBackToWizard = () => {
    setView('wizard')
    setCurrentStep(1)
  }

  // Don't render until we know if config exists
  if (!configLoaded) {
    return (
      <div className="app" style={{ alignItems: 'center', justifyContent: 'center' }}>
        <Loader2 className="spin" size={32} style={{ color: 'var(--primary-color)' }} />
      </div>
    )
  }

  return (
    <div className="app">
      <div className="sidebar">
        <Logo size="md" showText={true} animated={true} className="sidebar-logo" />
        
        {view === 'wizard' && currentStep < 4 && (
          <div className="steps-nav">
            {[
              { step: 1, label: 'Workspace' },
              { step: 2, label: 'Connection' },
              { step: 3, label: 'Pre-flight' },
            ].map(({ step, label }) => (
              <button
                key={step}
                type="button"
                className={`step-row ${step === currentStep ? 'active' : ''} ${step < currentStep ? 'completed' : ''}`}
                onClick={() => { if (step <= currentStep && !agentConnected) setCurrentStep(step) }}
                disabled={step > currentStep || (step < currentStep && agentConnected)}
              >
                <div className="step-dot">
                  {step < currentStep ? <CheckCircle size={16} /> : step}
                </div>
                <span className="step-label">{label}</span>
              </button>
            ))}
          </div>
        )}

        {/* Settings nav always available at bottom */}
        <div className="sidebar-nav">
          <button
            className={`sidebar-nav-item ${view === 'settings' ? 'active' : ''}`}
            onClick={() => setView('settings')}
          >
            <Settings size={18} />
            Settings
          </button>
        </div>
      </div>

      <div className="main-content">
        {(updater.checking || updater.message) && (
          <div className="update-banner" role="status">
            {updater.checking ? 'Checking for updates...' : updater.message}
          </div>
        )}

        {view === 'wizard' && (
          <>
            {currentStep === 1 && (
              <WorkspaceStep 
                config={config} 
                setConfig={setConfig} 
                onNext={() => setCurrentStep(2)} 
              />
            )}
            
            {currentStep === 2 && (
              <ConnectionStep 
                config={config} 
                setConfig={setConfig} 
                onNext={() => setCurrentStep(3)} 
                onPrev={() => setCurrentStep(1)} 
              />
            )}
            
            {currentStep === 3 && (
              <PreflightStep 
                config={config} 
                setConfig={setConfig} 
                onNext={handleWizardComplete} 
                onPrev={() => setCurrentStep(2)}
                onAgentConnected={() => setAgentConnected(true)}
              />
            )}

            {currentStep === 4 && <SuccessScreen onGoToSettings={handleGoToSettings} />}
          </>
        )}

        {view === 'settings' && (
          <SettingsView
            config={config}
            setConfig={setConfig}
            onBackToWizard={handleBackToWizard}
          />
        )}
      </div>
    </div>
  )
}

export default App
