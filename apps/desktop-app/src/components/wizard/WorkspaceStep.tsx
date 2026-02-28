import React, { useState, useCallback, useMemo } from 'react'
import { Folder, ArrowRight } from 'lucide-react'
import { motion } from 'framer-motion'
import { invoke } from '@tauri-apps/api/core'
import Button from '../ui/Button'
import Card from '../ui/Card'
import { StepProps } from '../../types'

const WorkspaceStep = React.memo<StepProps>(({
  config,
  setConfig,
  onNext,
  isLoading,
}) => {
  const [error, setError] = useState('')
  const [isSelecting, setIsSelecting] = useState(false)

  const handleSelectFolder = useCallback(async () => {
    setIsSelecting(true)
    setError('')
    
    try {
      const folder = await invoke<string | null>('select_folder')
      if (folder) {
        setConfig(prev => ({ ...prev, workspace_path: folder }))
      }
    } catch (err) {
      setError(String(err))
    } finally {
      setIsSelecting(false)
    }
  }, [setConfig])

  const canProceed = useMemo(() => 
    Boolean(config.workspace_path) && !isLoading && !isSelecting
  , [config.workspace_path, isLoading, isSelecting])

  const handleNext = useCallback(() => {
    if (canProceed) {
      onNext()
    }
  }, [canProceed, onNext])

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
          <Folder size={32} />
        </motion.div>
        <h2 className="step-title">Choose Workspace</h2>
        <p className="step-description">
          Select the folder where your projects will be stored
        </p>
      </div>

      <Card className="folder-picker-card" hover={false}>
        <div className="folder-display">
          <Folder size={20} className="folder-icon" />
          <span className={config.workspace_path ? 'folder-path' : 'folder-placeholder'}>
            {config.workspace_path || 'No folder selected'}
          </span>
        </div>
        
        <Button
          variant="secondary"
          onClick={handleSelectFolder}
          isLoading={isSelecting}
          className="folder-browse-btn"
        >
          Browse
        </Button>
      </Card>

      {error && (
        <motion.div
          className="error-banner"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
        >
          {error}
        </motion.div>
      )}

      <div className="step-actions">
        <div /> {/* Spacer for alignment */}
        <Button
          variant="primary"
          onClick={handleNext}
          disabled={!canProceed}
          isLoading={isLoading}
          rightIcon={<ArrowRight size={18} />}
        >
          Continue
        </Button>
      </div>
    </motion.div>
  )
})

WorkspaceStep.displayName = 'WorkspaceStep'

export default WorkspaceStep
