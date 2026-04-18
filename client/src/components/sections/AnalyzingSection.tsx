'use client'

import React from 'react'
import { motion } from 'framer-motion'

export default function AnalyzingSection() {
  return (
    <section className="relative py-20 px-4 sm:px-6 lg:px-10 overflow-hidden">
      {/* Bluish glow background */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="absolute w-96 h-96 bg-blue-500/30 rounded-full blur-3xl animate-pulse" />
        <div className="absolute w-72 h-72 bg-purple-500/20 rounded-full blur-3xl animate-pulse delay-1000" />
      </div>

      <div className="relative max-w-4xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="relative"
        >
          {/* Glassmorphic Card */}
          <div className="relative rounded-2xl border border-blue-400/30 bg-linear-to-br from-white/10 via-white/5 to-white/8 p-8 sm:p-12 backdrop-blur-xl shadow-[0_8px_32px_rgba(0,0,0,0.1)] overflow-hidden group hover:border-blue-400/50 transition-all duration-300">
            
            {/* Inner glow effect */}
            <div className="absolute inset-0 rounded-2xl bg-linear-to-r from-blue-500/5 via-transparent to-purple-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            
            {/* Content */}
            <div className="relative z-10 text-center">
              <motion.div
                initial={{ scale: 0.8, opacity: 0 }}
                whileInView={{ scale: 1, opacity: 1 }}
                transition={{ delay: 0.2, duration: 0.5 }}
                viewport={{ once: true }}
                className="inline-block mb-6"
              >
                <div className="flex items-center justify-center gap-2 px-4 py-2 rounded-full bg-blue-500/20 border border-blue-400/40">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
                  <span className="text-sm font-semibold text-blue-300">Live Analysis</span>
                </div>
              </motion.div>

              <motion.h2
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3, duration: 0.5 }}
                viewport={{ once: true }}
                className="text-3xl sm:text-4xl font-bold mb-4 text-white"
              >
                Analyzing Code for{' '}
                <span className="bg-linear-to-r from-blue-400 to-cyan-300 bg-clip-text text-transparent">
                  Malware
                </span>
              </motion.h2>

              <motion.p
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4, duration: 0.5 }}
                viewport={{ once: true }}
                className="text-[#a0aec0] text-lg max-w-2xl mx-auto mb-8 leading-relaxed"
              >
                Our advanced detection engine performs pre-clone repository checks, identifying potential malware threats, suspicious patterns, and security vulnerabilities using 1000+ data samples and license checker signals.
              </motion.p>

              {/* Stats */}
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5, duration: 0.5 }}
                viewport={{ once: true }}
                className="grid grid-cols-3 gap-6 max-w-3xl mx-auto"
              >
                <div className="p-8 rounded-xl bg-blue-500/10 border border-blue-400/20 hover:border-blue-400/40 transition-all">
                  <div className="text-4xl sm:text-5xl font-bold text-blue-400">1000+</div>
                  <div className="text-sm text-[#8b949e] mt-3">Data Samples</div>
                </div>
                <div className="p-8 rounded-xl bg-cyan-500/10 border border-cyan-400/20 hover:border-cyan-400/40 transition-all">
                  <div className="text-3xl sm:text-4xl font-bold text-cyan-400">Pre-</div>
                  <div className="text-3xl sm:text-4xl font-bold text-cyan-400">clone</div>
                  <div className="text-sm text-[#8b949e] mt-3">Detection</div>
                </div>
                <div className="p-8 rounded-xl bg-purple-500/10 border border-purple-400/20 hover:border-purple-400/40 transition-all">
                  <div className="text-2xl sm:text-3xl font-bold text-purple-400">License</div>
                  <div className="text-2xl sm:text-3xl font-bold text-purple-400">Checker</div>
                  <div className="text-sm text-[#8b949e] mt-3">Verification</div>
                </div>
              </motion.div>
            </div>

            {/* Animated border glow */}
            <div className="absolute inset-0 rounded-2xl bg-linear-to-r from-blue-500/0 via-blue-500/20 to-cyan-500/0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
          </div>
        </motion.div>
      </div>
    </section>
  )
}
