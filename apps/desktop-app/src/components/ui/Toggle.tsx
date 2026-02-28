import React, { useCallback } from 'react'
import { motion } from 'framer-motion'
import clsx from 'clsx'

interface ToggleProps {
  checked: boolean
  onChange: (checked: boolean) => void
  label?: string
  description?: string
  disabled?: boolean
  icon?: React.ReactNode
}

const Toggle = React.memo<ToggleProps>(({
  checked,
  onChange,
  label,
  description,
  disabled = false,
  icon,
}) => {
  const handleToggle = useCallback(() => {
    if (!disabled) {
      onChange(!checked)
    }
  }, [checked, disabled, onChange])

  return (
    <motion.div
      className={clsx('toggle-container', { 'toggle-disabled': disabled })}
      initial={false}
      animate={{ opacity: disabled ? 0.5 : 1 }}
    >
      <div className="toggle-content">
        {icon && <div className="toggle-icon">{icon}</div>}
        
        <div className="toggle-text">
          {label && <span className="toggle-label">{label}</span>}
          {description && <span className="toggle-description">{description}</span>}
        </div>
      </div>

      <button
        type="button"
        role="switch"
        aria-checked={checked}
        className={clsx('toggle-switch', { 'toggle-switch-checked': checked })}
        onClick={handleToggle}
        disabled={disabled}
      >
        <motion.span
          className="toggle-thumb"
          animate={{
            x: checked ? 24 : 0,
            backgroundColor: checked ? '#3b82f6' : '#64748b',
          }}
          transition={{ type: 'spring', stiffness: 500, damping: 30 }}
        />
        <motion.span
          className="toggle-track"
          animate={{
            backgroundColor: checked ? 'rgba(59, 130, 246, 0.3)' : 'rgba(100, 116, 139, 0.3)',
          }}
          transition={{ duration: 0.2 }}
        />
      </button>
    </motion.div>
  )
})

Toggle.displayName = 'Toggle'

export default Toggle
