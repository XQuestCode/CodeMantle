import React from 'react'
import { CheckCircle, Monitor } from 'lucide-react'
import { motion } from 'framer-motion'
import Card from '../ui/Card'

const SuccessScreen = React.memo(() => {
  return (
    <motion.div
      className="success-screen"
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5, type: 'spring', stiffness: 100 }}
    >
      <motion.div
        className="success-icon-wrapper"
        initial={{ scale: 0 }}
        animate={{ scale: 1 }}
        transition={{ 
          type: 'spring',
          stiffness: 200,
          delay: 0.2,
        }}
      >
        <div className="success-icon-bg">
          <CheckCircle size={64} className="success-icon" />
        </div>
        
        {/* Animated rings */}
        <motion.div
          className="success-ring ring-1"
          animate={{ 
            scale: [1, 1.5, 1.5],
            opacity: [0.5, 0, 0],
          }}
          transition={{ 
            duration: 2,
            repeat: Infinity,
            repeatDelay: 0.5,
          }}
        />
        <motion.div
          className="success-ring ring-2"
          animate={{ 
            scale: [1, 1.8, 1.8],
            opacity: [0.3, 0, 0],
          }}
          transition={{ 
            duration: 2,
            repeat: Infinity,
            repeatDelay: 0.5,
            delay: 0.3,
          }}
        />
      </motion.div>

      <motion.h2
        className="success-title"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        Setup Complete!
      </motion.h2>

      <motion.p
        className="success-message"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        CodeMantle is now running and ready to use.
      </motion.p>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
      >
        <Card className="success-info-card" hover={false}>
          <Monitor size={24} className="success-info-icon" />
          <div className="success-info-content">
            <h3>System Tray Active</h3>
            <p>
              The agent will minimize to the system tray. Click the tray icon to show or hide the window.
            </p>
          </div>
        </Card>
      </motion.div>

      <motion.p
        className="success-footer"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.8 }}
      >
        You can close this window. The agent will continue running in the background.
      </motion.p>
    </motion.div>
  )
})

SuccessScreen.displayName = 'SuccessScreen'

export default SuccessScreen
