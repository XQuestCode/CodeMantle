export interface SetupConfig {
  workspace_path: string
  control_plane_url: string
  auth_token: string
  start_on_boot: boolean
}

export interface StepProps {
  config: SetupConfig
  setConfig: React.Dispatch<React.SetStateAction<SetupConfig>>
  onNext: () => void
  onPrev?: () => void
  isLoading?: boolean
}

export type ConnectionStatus = 'idle' | 'checking' | 'ready' | 'error'

export interface LogEntry {
  id: string
  timestamp: number
  message: string
  type: 'stdout' | 'stderr' | 'system'
}
