import React, { useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import clsx from 'clsx'

interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  label?: string
  error?: string
  helperText?: string
  onChange?: (value: string) => void
}

const Input = React.memo<InputProps>(({
  label,
  error,
  helperText,
  onChange,
  className,
  value,
  type = 'text',
  ...props
}) => {
  const [isFocused, setIsFocused] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const isPassword = type === 'password'
  const hasValue = Boolean(value)

  const handleFocus = useCallback(() => setIsFocused(true), [])
  const handleBlur = useCallback((e: React.FocusEvent<HTMLInputElement>) => {
    setIsFocused(false)
    props.onBlur?.(e)
  }, [props.onBlur])

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    onChange?.(e.target.value)
  }, [onChange])

  const togglePassword = useCallback(() => {
    setShowPassword(prev => !prev)
  }, [])

  const inputType = isPassword && showPassword ? 'text' : type

  return (
    <div className={clsx('input-container', className)}>
      {label && (
        <motion.label
          className={clsx('input-label', {
            'input-label-floating': isFocused || hasValue,
            'input-label-error': error,
          })}
          animate={{
            y: isFocused || hasValue ? -24 : 0,
            scale: isFocused || hasValue ? 0.85 : 1,
            color: error ? '#ef4444' : isFocused ? '#3b82f6' : '#94a3b8',
          }}
          transition={{ duration: 0.2 }}
        >
          {label}
        </motion.label>
      )}
      
      <div className="input-wrapper">
        <input
          {...props}
          type={inputType}
          value={value}
          onChange={handleChange}
          onFocus={handleFocus}
          onBlur={handleBlur}
          className={clsx('input-field', {
            'input-field-error': error,
            'input-field-focused': isFocused,
            'input-field-with-toggle': isPassword,
          })}
        />
        
        {isPassword && (
          <button
            type="button"
            className="input-toggle-password"
            onClick={togglePassword}
            tabIndex={-1}
          >
            {showPassword ? 'Hide' : 'Show'}
          </button>
        )}
      </div>

      <motion.div
        className="input-underline"
        initial={{ scaleX: 0 }}
        animate={{ scaleX: isFocused ? 1 : 0 }}
        transition={{ duration: 0.2 }}
      />

      {error && (
        <motion.span
          className="input-error"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
        >
          {error}
        </motion.span>
      )}
      
      {helperText && !error && (
        <span className="input-helper">{helperText}</span>
      )}
    </div>
  )
})

Input.displayName = 'Input'

export default Input
