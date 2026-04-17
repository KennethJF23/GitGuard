'use client'

import React from 'react'
import { motion } from 'framer-motion'
import Button from '@/components/ui/Button'

const FinalCta: React.FC = () => {
  return (
    <section className="py-16 bg-gray-50">
      <div className="container mx-auto px-4">
        <motion.div
          className="max-w-4xl mx-auto bg-white rounded-2xl shadow-xl border border-gray-100 p-8 md:p-12 text-center"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          viewport={{ once: true }}
        >
          <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
            Ready to evaluate repositories smarter?
          </h2>
          <p className="text-lg text-gray-600 max-w-2xl mx-auto mb-8">
            Join developers making secure and confident decisions with GitGuard
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-6">
            <Button href="/human-analysis" variant="primary" size="medium">
              Get started for free
            </Button>
            <Button href="/login" variant="secondary" size="medium">
              Sign in
            </Button>
          </div>

          <p className="text-sm text-gray-500">
            No credit card required • Free forever • GitHub API powered
          </p>
        </motion.div>
      </div>
    </section>
  )
}

export default FinalCta
