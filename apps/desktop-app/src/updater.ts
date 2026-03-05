import { useEffect, useRef, useState } from 'react'
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

  // Guards: prevent concurrent checks, duplicate dialogs, and re-checks after install
  const busyRef = useRef(false)
  const installedRef = useRef(false)
  const dialogOpenRef = useRef(false)

  useEffect(() => {
    let cancelled = false
    const mode = resolveUpdaterMode()

    const checkForUpdates = async () => {
      // Skip if already checking, dialog is open, or update was already installed
      if (busyRef.current || dialogOpenRef.current || installedRef.current) return

      busyRef.current = true
      setState(prev => ({ ...prev, checking: true }))
      try {
        const update = await check()
        if (cancelled) return

        if (!update) {
          setState(prev => ({ ...prev, checking: false, message: '' }))
          return
        }

        if (mode === 'prompt') {
          dialogOpenRef.current = true
          let shouldInstall = false
          try {
            shouldInstall = await ask(
              `CodeMantle ${update.version} is available. Download and install now?`,
              { title: 'Update Available', kind: 'info' },
            )
          } finally {
            dialogOpenRef.current = false
          }

          if (cancelled) return

          if (!shouldInstall) {
            setState({
              checking: false,
              message: `Update ${update.version} available — install from Settings or restart.`,
              hasPendingRestart: false,
            })
            return
          }
        }

        await update.downloadAndInstall()
        if (!cancelled) {
          installedRef.current = true
          setState({
            checking: false,
            message: `Update ${update.version} installed. Restart the app to apply it.`,
            hasPendingRestart: true,
          })
        }
      } catch {
        // Silently swallow update check failures — don't spam the banner
        if (!cancelled) {
          setState(prev => ({ ...prev, checking: false }))
        }
      } finally {
        busyRef.current = false
      }
    }

    // Delay the first check to let the window render first
    const initialDelay = setTimeout(() => {
      void checkForUpdates()
    }, 5000)

    const timer = setInterval(() => {
      void checkForUpdates()
    }, UPDATE_POLL_INTERVAL_MS)

    return () => {
      cancelled = true
      clearTimeout(initialDelay)
      clearInterval(timer)
    }
  }, [])

  return state
}
