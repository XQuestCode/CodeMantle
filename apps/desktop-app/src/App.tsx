import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { Folder, Settings, CheckCircle, Loader2, Terminal, ArrowRight, ArrowLeft, Monitor } from 'lucide-react'
import './App.css'
import { useAutoUpdater } from './updater'
import Logo from './components/ui/Logo'

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
          onClick={onNext}
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

  const validate = () => {
    const newErrors: {[key: string]: string} = {}
    
    if (!config.control_plane_url) {
      newErrors.control_plane_url = 'Control Plane URL is required'
    } else if (!config.control_plane_url.startsWith('wss://') && !config.control_plane_url.startsWith('ws://')) {
      newErrors.control_plane_url = 'URL must start with ws:// or wss://'
    }
    
    if (!config.auth_token) {
      newErrors.auth_token = 'Auth token is required'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleNext = () => {
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
        <label>Control Plane URL</label>
        <input
          type="text"
          value={config.control_plane_url}
          onChange={(e) => setConfig(prev => ({ ...prev, control_plane_url: e.target.value }))}
          placeholder="wss://codemantle.cloud/ws"
          className={errors.control_plane_url ? 'error' : ''}
        />
        {errors.control_plane_url && <span className="field-error">{errors.control_plane_url}</span>}
      </div>

      <div className="form-group">
        <label>Agent Auth Token</label>
        <input
          type="password"
          value={config.auth_token}
          onChange={(e) => setConfig(prev => ({ ...prev, auth_token: e.target.value }))}
          placeholder="Enter your auth token"
          className={errors.auth_token ? 'error' : ''}
        />
        {errors.auth_token && <span className="field-error">{errors.auth_token}</span>}
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

    return () => {
      unlisten.then(f => f())
      unlistenStatus.then(f => f())
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

// Success Screen
function SuccessScreen() {
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
    </div>
  )
}

function App() {
  const updater = useAutoUpdater()
  const [currentStep, setCurrentStep] = useState(1)
  const [config, setConfig] = useState<SetupConfig>({
    workspace_path: '',
    control_plane_url: 'wss://codemantle.cloud/ws',
    auth_token: '',
    start_on_boot: false,
  })

  return (
    <div className="app">
      <div className="sidebar">
        <Logo size="md" showText={true} animated={true} className="sidebar-logo" />
        
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
      </div>

      <div className="main-content">
        {(updater.checking || updater.message) && (
          <div className="update-banner" role="status">
            {updater.checking ? 'Checking for updates...' : updater.message}
          </div>
        )}

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
            onNext={() => setCurrentStep(4)} 
            onPrev={() => setCurrentStep(2)} 
          />
        )}

        {currentStep === 4 && <SuccessScreen />}
      </div>
    </div>
  )
}

export default App
