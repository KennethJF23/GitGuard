'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { Biohazard, Skull, Target } from 'lucide-react'
import { ArrowRight } from 'lucide-react'

const Technologies: React.FC = () => {
  const technologies = [
    {
      title: 'Keyword intelligence',
      icon: Biohazard,
      href: '/platform',
      color: 'text-red-500'
    },
    {
      title: 'ZIP source scanning',
      icon: Skull,
      href: '/platform',
      color: 'text-red-600'
    },
    {
      title: 'Deterministic verdict engine',
      icon: Target,
      href: '/platform',
      color: 'text-red-700'
    }
  ]

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        duration: 0.6,
        staggerChildren: 0.2
      }
    }
  }

  const cardVariants = {
    hidden: { y: 30, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        duration: 0.5
      }
    }
  }

  return (
    <section className="py-16 bg-black text-white">
      <div className="container mx-auto px-4">
        {/* Section Title */}
        <motion.div
          className="text-center mb-16"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <div className="inline-flex items-center justify-center mb-8">
            <div className="h-px bg-white/20 w-20"></div>
            <h2 className="px-6 text-2xl font-semibold uppercase tracking-wider">
              Detection pipeline
            </h2>
            <div className="h-px bg-white/20 w-20"></div>
          </div>
        </motion.div>

        {/* Technology Cards */}
        <motion.div
          className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto"
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
        >
          {technologies.map((tech, index) => (
            <motion.div
              key={index}
              variants={cardVariants}
              className="group relative cursor-pointer"
              whileHover={{ y: -10 }}
              transition={{ duration: 0.3 }}
            >
              {/* Background Icons */}
              <div className="absolute inset-0 flex items-center justify-center opacity-10">
                <div className="flex space-x-2">
                  {[...Array(3)].map((_, i) => (
                    <tech.icon
                      key={i}
                      className={`w-16 h-16 ${tech.color}`}
                      style={{
                        animation: `float ${3 + i * 0.5}s ease-in-out infinite`,
                        animationDelay: `${i * 0.2}s`
                      }}
                    />
                  ))}
                </div>
              </div>

              {/* Card Content */}
              <div className="relative bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 hover:bg-white/10 transition-all duration-300">
                <div className="flex flex-col items-center text-center">
                  {/* Icon */}
                  <div className={`mb-6 ${tech.color}`}>
                    <tech.icon className="w-12 h-12" />
                  </div>

                  {/* Title */}
                  <h3 className="text-xl font-semibold mb-4">
                    <a
                      href={tech.href}
                      className="hover:text-blue-400 transition-colors"
                    >
                      {tech.title}
                    </a>
                  </h3>

                  {/* Arrow */}
                  <div className="flex items-center text-blue-400 group-hover:text-blue-300 transition-colors">
                    <ArrowRight className="w-5 h-5" />
                  </div>
                </div>
              </div>

              {/* Hover Effect */}
              <div className="absolute inset-0 bg-gradient-to-t from-blue-600/20 to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
            </motion.div>
          ))}
        </motion.div>
      </div>

      <style jsx>{`
        @keyframes float {
          0%, 100% {
            transform: translateY(0px);
          }
          50% {
            transform: translateY(-10px);
          }
        }
      `}</style>
    </section>
  )
}

export default Technologies
