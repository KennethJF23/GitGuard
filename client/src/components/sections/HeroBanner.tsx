'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { Globe, Atom, Lock, Database, Send, AtSign } from 'lucide-react'
import Button from '../ui/Button'
import { SocialOrbit } from '../ui/social-orbit'

const HeroBanner: React.FC = () => {
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        duration: 0.6,
        staggerChildren: 0.1
      }
    }
  }

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        duration: 0.5
      }
    }
  }

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden bg-gradient-to-br from-blue-50 to-white">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-blue-600/10 to-purple-600/10"></div>
        
        {/* Social Orbit Bubbles */}
        <div className="absolute inset-0 flex items-center justify-center mb-32" style={{ marginBottom: '50px' }}>
          <SocialOrbit
            rippleCount={6}
            text='GITGUARD'
            rippleDuration={3}
            textOrbitIndex={2}
            textDuration={20}
            orbitDuration={30}
            iconDelay={200}
            iconDuration={800}
            className="w-32 h-32"
          />
        </div>
      </div>

      {/* Content */}
      <motion.div
        className="relative z-10 text-center px-4 max-w-4xl mx-auto"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        <motion.h1
          className="text-4xl md:text-6xl font-bold text-gray-900 mb-6 leading-tight"
          variants={itemVariants}
        >
          GitGuard scans GitHub repositories for malware risk
        </motion.h1>
        
        <motion.div
          className="text-lg md:text-xl text-gray-600 mb-8 max-w-2xl mx-auto"
          variants={itemVariants}
        >
          Run backend-powered analysis with{' '}
          <span className="font-semibold text-blue-600">keyword intelligence, ZIP source scanning, and deterministic verdicts</span>
          {' '}for SAFE, SUSPICIOUS, MALICIOUS, or DANGEROUS DATASET outcomes.
        </motion.div>
        
        <motion.div variants={itemVariants}>
          <Button
            href="/platform"
            variant="primary"
            size="large"
            className="inline-flex"
          >
            Start a GitGuard scan
          </Button>
        </motion.div>
      </motion.div>

      {/* Gradient Overlay */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-white to-transparent"></div>
    </section>
  )
}

export default HeroBanner
