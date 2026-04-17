'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { Link2, ScanSearch, ShieldCheck, CircleCheckBig } from 'lucide-react'

const steps = [
  {
    step: '01',
    title: 'Enter Repository URL',
    description: 'Paste any GitHub repository URL to begin analysis',
    icon: Link2
  },
  {
    step: '02',
    title: 'Automated Analysis',
    description: 'Our system scans for licenses, code quality, and security risks',
    icon: ScanSearch
  },
  {
    step: '03',
    title: 'Get Trust Score',
    description: 'Receive a detailed reliability score with insights',
    icon: ShieldCheck
  },
  {
    step: '04',
    title: 'Make Informed Decision',
    description: 'Use insights to choose safe and high-quality repositories',
    icon: CircleCheckBig
  }
]

const HowItWorks: React.FC = () => {
  return (
    <section className="py-16 bg-white">
      <div className="container mx-auto px-4">
        <motion.div
          className="text-center mb-16"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <div className="inline-flex items-center justify-center mb-8">
            <div className="h-px bg-gray-300 w-20"></div>
            <h2 className="px-6 text-2xl font-semibold uppercase tracking-wider text-gray-900">
              How It Works
            </h2>
            <div className="h-px bg-gray-300 w-20"></div>
          </div>
          <h3 className="text-3xl md:text-4xl font-bold text-gray-900 max-w-4xl mx-auto">
            Get comprehensive repository insights in four simple steps
          </h3>
        </motion.div>

        <motion.div
          className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-6"
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          variants={{
            hidden: { opacity: 0 },
            visible: {
              opacity: 1,
              transition: {
                staggerChildren: 0.12,
                duration: 0.4
              }
            }
          }}
        >
          {steps.map((item) => (
            <motion.article
              key={item.step}
              variants={{
                hidden: { opacity: 0, y: 16 },
                visible: { opacity: 1, y: 0 }
              }}
              className="bg-white rounded-2xl shadow-xl border border-gray-100 p-6 transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl"
            >
              <div className="flex items-center justify-between mb-4">
                <span className="text-sm font-semibold text-gray-500 uppercase tracking-wide">Step {item.step}</span>
                <div className="h-10 w-10 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center">
                  <item.icon className="w-5 h-5" />
                </div>
              </div>
              <h4 className="text-xl font-semibold text-gray-900 mb-3">{item.title}</h4>
              <p className="text-sm text-gray-600 leading-relaxed">{item.description}</p>
            </motion.article>
          ))}
        </motion.div>
      </div>
    </section>
  )
}

export default HowItWorks
