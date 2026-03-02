import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { Folder, Settings, CheckCircle, Loader2, Terminal, ArrowRight, ArrowLeft, Monitor, Info, Eye, EyeOff } from 'lucide-react'
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
          placeholder="codemantle.cloud/ws"
          className={errors.control_plane_url ? 'error' : ''}
        />
        <span className="field-helper">Enter your server domain (e.g. myserver.com). Protocol is added automatically.</span>
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
function PreflightStep({ config, setConfig, onNext, onPrev }: StepProps) {
  const [status, setStatus] = useState<'idle' | 'checking' | 'ready' | 'error'>('idle')
  const [logs, setLogs] = useState<string[]>([])
  const [autostartEnabled, setAutostartEnabled] = useState(config.start_on_boot)

  useEffect(() => {
    // Listen for agent logs
    const unlisten = listen<string>('agent-log', (event) => {
      setLogs(prev => [...prev, event.payload])
    })

    // Listen for connection status
    const unlistenStatus = listen<{connected: boolean; first_time: boolean}>('connection-status', (event) => {
      if (event.payload.connected) {
        setStatus('ready')
      }
    })

    // Listen for agent exit (crash / unexpected termination)
    const unlistenExit = listen<number>('agent-exit', (event) => {
      setStatus('error')
      setLogs(prev => [...prev, `Agent process exited with code ${event.payload}`])
    })

    return () => {
      unlisten.then(f => f())
      unlistenStatus.then(f => f())
      unlistenExit.then(f => f())
    }
  }, [])

  const handleStartAgent = async () => {
    setStatus('checking')
    setLogs([])
    
    try {
      await invoke('start_agent_daemon', { config })
    } catch (err) {
      setStatus('error')
      setLogs(prev => [...prev, `Error: ${err}`])
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
          </div>
        )}

        {status === 'ready' && (
          <div className="ready-status">
            <CheckCircle size={24} className="success-icon" />
            <span>Agent connected successfully!</span>
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
        <button className="btn-secondary" onClick={onPrev}>
          <ArrowLeft size={20} />
          Back
        </button>
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
  const [config, setConfig] = useState<SetupConfig>({
    workspace_path: '',
    control_plane_url: 'codemantle.cloud/ws',
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
          <>
            <div className="steps-indicator">
              {[1, 2, 3].map((step) => (
                <div 
                  key={step} 
                  className={`step-dot ${step === currentStep ? 'active' : ''} ${step < currentStep ? 'completed' : ''}`}
                >
                  {step < currentStep ? <CheckCircle size={16} /> : step}
                </div>
              ))}
            </div>
            
            <div className="step-labels">
              <span className={currentStep === 1 ? 'active' : ''}>Workspace</span>
              <span className={currentStep === 2 ? 'active' : ''}>Connection</span>
              <span className={currentStep === 3 ? 'active' : ''}>Pre-flight</span>
            </div>
          </>
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
