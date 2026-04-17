'use client'

import React from 'react'
import { motion } from 'framer-motion'
import Button from '../ui/Button'

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
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden bg-linear-to-br from-blue-50 to-white">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute inset-0 bg-linear-to-br from-blue-600/10 to-purple-600/10"></div>
      </div>

      {/* Content */}
      <motion.div
        className="relative z-10 px-4 max-w-6xl mx-auto w-full"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-10 items-center">
          <div className="text-center md:text-left">
            <motion.h1
              className="text-4xl md:text-6xl font-bold mb-6 leading-tight bg-linear-to-r from-blue-950 via-slate-900 to-black bg-clip-text text-transparent"
              variants={itemVariants}
            >
              GITGUARD
            </motion.h1>

            <motion.div
              className="text-lg md:text-xl mb-8 max-w-2xl bg-linear-to-r from-blue-900 via-slate-800 to-black bg-clip-text text-transparent"
              variants={itemVariants}
            >
              GitGuard scans GitHub repositories for malware risk
            </motion.div>

            <motion.div variants={itemVariants}>
              <Button
                href="/login"
                variant="primary"
                size="large"
                className="inline-flex"
              >
                Start a GitGuard scan
              </Button>
            </motion.div>
          </div>

          <motion.div
            className="relative"
            variants={itemVariants}
          >
            <div className="rounded-2xl overflow-hidden border border-blue-900/20 shadow-2xl bg-black/80">
              <video
                className="w-full h-auto"
                autoPlay
                muted
                loop
                playsInline
                onError={(e) => {
                  const target = e.target as HTMLVideoElement;
                  target.style.display = 'none';
                  const parent = target.parentElement;
                  if (parent) {
                    parent.innerHTML = '<div class="w-full h-64 bg-linear-to-br from-blue-950 to-black flex items-center justify-center text-blue-100">GitGuard Demo</div>';
                  }
                }}
              >
                <source src="/videos/kling_20260417_作品_Video_Back_336_0 (1).mp4" type="video/mp4" />
                <source src="/videos/plateforme.webm" type="video/webm" />
              </video>
            </div>
          </motion.div>
        </div>
      </motion.div>

      {/* Gradient Overlay */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-linear-to-t from-white to-transparent"></div>
    </section>
  )
}

export default HeroBanner
