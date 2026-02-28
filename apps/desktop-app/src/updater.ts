import { useEffect, useState } from 'react'
import { ask } from '@tauri-apps/plugin-dialog'
import { check } from '@tauri-apps/plugin-updater'

const UPDATE_POLL_INTERVAL_MS = 1000 * 60 * 30

type UpdaterMode = 'prompt' | 'silent'

export interface UpdaterState {
  checking: boolean
  message: string
  hasPendingRestart: boolean
}

function resolveUpdaterMode(): UpdaterMode {
  const value = (import.meta.env.VITE_CODEMANTLE_UPDATER_MODE ?? 'prompt').toLowerCase()
  return value === 'silent' ? 'silent' : 'prompt'
}

export function useAutoUpdater(): UpdaterState {
  const [state, setState] = useState<UpdaterState>({
    checking: false,
    message: '',
    hasPendingRestart: false,
  })

  useEffect(() => {
    let cancelled = false
    const mode = resolveUpdaterMode()

    const checkForUpdates = async () => {
      setState(prev => ({ ...prev, checking: true }))
      try {
        const update = await check()
        if (!update) {
          if (!cancelled) {
            setState(prev => ({ ...prev, checking: false, message: '' }))
          }
          return
        }

        if (mode === 'prompt') {
          const shouldInstall = await ask(
            `CodeMantle ${update.version} is available. Download and install now?`,
            { title: 'Update Available', kind: 'info' },
          )
          if (!shouldInstall) {
            if (!cancelled) {
              setState({
                checking: false,
                message: `Update ${update.version} is available`,
                hasPendingRestart: false,
              })
            }
            return
          }
        }

        await update.downloadAndInstall()
        if (!cancelled) {
          setState({
            checking: false,
            message: `Update ${update.version} installed. Restart the app to apply it.`,
            hasPendingRestart: true,
          })
        }
      } catch (error) {
        if (!cancelled) {
          const message = error instanceof Error ? error.message : 'Update check failed'
          setState(prev => ({ ...prev, checking: false, message }))
        }
      }
    }

    void checkForUpdates()
    const timer = setInterval(() => {
      void checkForUpdates()
    }, UPDATE_POLL_INTERVAL_MS)

    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

  return state
}
