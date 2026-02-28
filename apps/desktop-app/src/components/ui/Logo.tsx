import React from 'react'
import { motion } from 'framer-motion'

interface LogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl'
  showText?: boolean
  animated?: boolean
  className?: string
}

const sizeMap = {
  sm: { img: 32, text: 'text-lg' },
  md: { img: 40, text: 'text-xl' },
  lg: { img: 48, text: 'text-2xl' },
  xl: { img: 64, text: 'text-3xl' },
}

const Logo = React.memo<LogoProps>(({
  size = 'md',
  showText = true,
  animated = true,
  className = '',
}) => {
  const { img, text } = sizeMap[size]

  return (
    <motion.div 
      className={`logo-container ${className}`}
      initial={animated ? { opacity: 0, y: -10 } : false}
      animate={animated ? { opacity: 1, y: 0 } : false}
      transition={{ duration: 0.5 }}
    >
      <motion.div
        className="logo-image-wrapper"
        whileHover={animated ? { scale: 1.05, rotate: 5 } : undefined}
        transition={{ type: 'spring', stiffness: 400, damping: 10 }}
      >
        <img
          src="/assets/logo-128.png"
          alt="CodeMantle Logo"
          width={img}
          height={img}
          className="logo-image"
          style={{ 
            filter: 'drop-shadow(0 4px 8px rgba(59, 130, 246, 0.3))',
          }}
        />
      </motion.div>
      
      {showText && (
        <motion.span 
          className={`logo-text ${text}`}
          initial={animated ? { opacity: 0, x: -10 } : false}
          animate={animated ? { opacity: 1, x: 0 } : false}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          CodeMantle
        </motion.span>
      )}
    </motion.div>
  )
})

Logo.displayName = 'Logo'

export default Logo
