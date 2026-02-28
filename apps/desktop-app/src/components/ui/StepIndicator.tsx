import React, { useMemo } from 'react'
import { motion } from 'framer-motion'
import { CheckCircle, Circle } from 'lucide-react'
import clsx from 'clsx'

interface Step {
  id: number
  label: string
  description?: string
}

interface StepIndicatorProps {
  steps: Step[]
  currentStep: number
  className?: string
}

const StepIndicator = React.memo<StepIndicatorProps>(({
  steps,
  currentStep,
  className,
}) => {
  const stepStates = useMemo(() => {
    return steps.map((step) => ({
      ...step,
      isCompleted: step.id < currentStep,
      isActive: step.id === currentStep,
      isPending: step.id > currentStep,
    }))
  }, [steps, currentStep])

  return (
    <div className={clsx('step-indicator', className)}>
      {stepStates.map((step, index) => (
        <React.Fragment key={step.id}>
          <motion.div
            className={clsx('step-item', {
              'step-completed': step.isCompleted,
              'step-active': step.isActive,
              'step-pending': step.isPending,
            })}
            initial={false}
            animate={{
              scale: step.isActive ? 1.05 : 1,
            }}
            transition={{ duration: 0.2 }}
          >
            <motion.div
              className={clsx('step-dot')}
              animate={{
                backgroundColor: step.isCompleted
                  ? '#22c55e'
                  : step.isActive
                  ? '#3b82f6'
                  : 'rgba(100, 116, 139, 0.3)',
                borderColor: step.isActive ? '#3b82f6' : 'transparent',
              }}
              transition={{ duration: 0.3 }}
            >
              {step.isCompleted ? (
                <CheckCircle size={16} className="step-icon" />
              ) : step.isActive ? (
                <Circle size={16} className="step-icon" />
              ) : (
                <span className="step-number">{step.id}</span>
              )}
            </motion.div>

            <div className="step-info">
              <motion.span
                className="step-label"
                animate={{
                  color: step.isActive ? '#f8fafc' : '#94a3b8',
                  fontWeight: step.isActive ? 600 : 400,
                }}
              >
                {step.label}
              </motion.span>
              {step.description && (
                <span className="step-description">{step.description}</span>
              )}
            </div>
          </motion.div>

          {index < steps.length - 1 && (
            <motion.div
              className="step-connector"
              initial={false}
              animate={{
                backgroundColor: step.isCompleted
                  ? '#22c55e'
                  : 'rgba(100, 116, 139, 0.3)',
              }}
              transition={{ duration: 0.3 }}
            />
          )}
        </React.Fragment>
      ))}
    </div>
  )
})

StepIndicator.displayName = 'StepIndicator'

export default StepIndicator
