import React from 'react'
import { motion } from 'framer-motion'
import clsx from 'clsx'

interface CardProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'onAnimationStart' | 'onAnimationEnd' | 'onDragStart' | 'onDrag' | 'onDragEnd'> {
  variant?: 'default' | 'glass' | 'elevated'
  padding?: 'sm' | 'md' | 'lg'
  hover?: boolean
}

const Card = React.memo<CardProps>(({
  children,
  variant = 'glass',
  padding = 'md',
  hover = true,
  className,
  ...props
}) => {
  const baseClasses = clsx(
    'card',
    {
      'card-default': variant === 'default',
      'card-glass': variant === 'glass',
      'card-elevated': variant === 'elevated',
      'card-padding-sm': padding === 'sm',
      'card-padding-md': padding === 'md',
      'card-padding-lg': padding === 'lg',
    },
    className
  )

  return (
    <motion.div
      className={baseClasses}
      initial={false}
      whileHover={hover ? { y: -2, boxShadow: '0 8px 30px rgba(0, 0, 0, 0.3)' } : undefined}
      transition={{ duration: 0.2 }}
      {...props}
    >
      {children}
    </motion.div>
  )
})

Card.displayName = 'Card'

export default Card
