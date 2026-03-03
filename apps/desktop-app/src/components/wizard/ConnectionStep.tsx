import React, { useState, useCallback, useMemo } from 'react'
import { Settings, ArrowRight, ArrowLeft } from 'lucide-react'
import { motion } from 'framer-motion'
import Button from '../ui/Button'
import Input from '../ui/Input'
import { StepProps } from '../../types'
import { normalizeControlPlaneUrl, validateControlPlaneUrl } from '../../utils'

interface FormErrors {
  control_plane_url?: string
  auth_token?: string
  workspace_path?: string
  start_on_boot?: string
}

const ConnectionStep = React.memo<StepProps>(({
  config,
  setConfig,
  onNext,
  onPrev,
  isLoading,
}) => {
  const [errors, setErrors] = useState<FormErrors>({})
  const [touched, setTouched] = useState<Record<string, boolean>>({})

  const validateField = useCallback((name: string, value: string): string | undefined => {
    switch (name) {
      case 'control_plane_url':
        return validateControlPlaneUrl(value)
      case 'auth_token':
        if (!value) return 'Auth token is required'
        if (value.length < 10) return 'Auth token must be at least 10 characters'
        return undefined
      default:
        return undefined
    }
  }, [])

  const validateForm = useCallback((): boolean => {
    const newErrors: FormErrors = {}
    
    const urlError = validateField('control_plane_url', config.control_plane_url)
    if (urlError) newErrors.control_plane_url = urlError
    
    const tokenError = validateField('auth_token', config.auth_token)
    if (tokenError) newErrors.auth_token = tokenError

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }, [config, validateField])

  const handleChange = useCallback((field: keyof typeof config) => (value: string | boolean) => {
    setConfig(prev => ({ ...prev, [field]: value }))
    
    // Clear error when user types
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: undefined }))
    }
  }, [setConfig, errors])

  const handleBlur = useCallback((field: keyof typeof config) => () => {
    setTouched(prev => ({ ...prev, [field]: true }))
    const value = config[field]
    if (typeof value === 'string') {
      // Normalize the URL on blur so the user sees the resolved value
      if (field === 'control_plane_url' && value) {
        const normalized = normalizeControlPlaneUrl(value)
        if (normalized !== value) {
          setConfig(prev => ({ ...prev, control_plane_url: normalized }))
        }
        const error = validateControlPlaneUrl(normalized)
        if (error) {
          setErrors(prev => ({ ...prev, [field]: error }))
        }
        return
      }
      const error = validateField(field, value)
      if (error) {
        setErrors(prev => ({ ...prev, [field]: error }))
      }
    }
  }, [config, validateField, setConfig])

  const handleNext = useCallback(() => {
    // Normalize the URL before final validation
    if (config.control_plane_url) {
      const normalized = normalizeControlPlaneUrl(config.control_plane_url)
      if (normalized !== config.control_plane_url) {
        setConfig(prev => ({ ...prev, control_plane_url: normalized }))
      }
    }
    setTouched({ control_plane_url: true, auth_token: true })
    if (validateForm()) {
      onNext()
    }
  }, [config.control_plane_url, setConfig, validateForm, onNext])

  const canProceed = useMemo(() => 
    Boolean(config.control_plane_url && config.auth_token) && !isLoading
  , [config.control_plane_url, config.auth_token, isLoading])

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
          <Settings size={32} />
        </motion.div>
        <h2 className="step-title">Connection Settings</h2>
        <p className="step-description">
          Configure how CodeMantle connects to the cloud
        </p>
      </div>

      <div className="form-container">
        <Input
          label="Control Plane Server"
          value={config.control_plane_url}
          onChange={handleChange('control_plane_url')}
          onBlur={handleBlur('control_plane_url')}
          placeholder="codemantle.cloud"
          error={touched.control_plane_url ? errors.control_plane_url : undefined}
          helperText="Enter your server domain (e.g. myserver.com). Protocol and /ws path are added automatically."
        />

        <Input
          label="Agent Auth Token"
          type="password"
          value={config.auth_token}
          onChange={handleChange('auth_token')}
          onBlur={handleBlur('auth_token')}
          placeholder="Enter your auth token"
          error={touched.auth_token ? errors.auth_token : undefined}
          helperText="Your secure authentication token"
        />
      </div>

      <div className="step-actions">
        <Button
          variant="ghost"
          onClick={onPrev}
          disabled={isLoading}
          leftIcon={<ArrowLeft size={18} />}
        >
          Back
        </Button>
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

ConnectionStep.displayName = 'ConnectionStep'

export default ConnectionStep
