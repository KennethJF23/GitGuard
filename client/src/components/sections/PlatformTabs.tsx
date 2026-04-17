'use client'

import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Users, GraduationCap, Lock } from 'lucide-react'
import Button from '../ui/Button'
import Image from 'next/image'

const PlatformTabs: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0)

  const tabs = [
    {
      id: 'analyze',
      title: 'Repository Analyze',
      preTitle: 'Analyze Module',
      description: 'Parse owner/repo input and collect GitHub metadata for risk context',
      content: 'GitGuard accepts full GitHub URLs or owner/repo shorthand, validates repository identity, and gathers metadata like topics, languages, and README text before scoring.',
      videoSrc: null,
      imageSrc: '/images/pawel-czerwinski-8uZPynIu-rQ-unsplash-scaled.webp',
      icon: Shield,
      href: '/platform'
    },
    {
      id: 'scan',
      title: 'Malware Scan Pipeline',
      preTitle: 'Scan Module',
      description: 'Download zipballs, filter files, and match substring/regex indicators',
      content: 'The pipeline downloads repository archives, extracts source files, skips noisy paths, and scans allowed file types against MongoDB-managed malware keywords with weighted scoring.',
      videoSrc: null,
      imageSrc: '/images/pawel-czerwinski-8uZPynIu-rQ-unsplash-scaled.webp',
      icon: Shield,
      href: '/platform'
    },
    {
      id: 'verdict',
      title: 'Verdict Engine',
      preTitle: 'Classification Module',
      description: 'Generate deterministic outcomes from score, categories, and dataset signals',
      content: 'GitGuard classifies repositories into SAFE, SUSPICIOUS, MALICIOUS, or DANGEROUS DATASET using explicit rules, high-risk category combinations, and confidence checks.',
      videoSrc: null,
      imageSrc: '/images/pawel-czerwinski-8uZPynIu-rQ-unsplash-scaled.webp',
      icon: Users,
      href: '/platform'
    },
    {
      id: 'cache',
      title: 'Caching & Performance',
      preTitle: 'Cache Module',
      description: 'Reuse previous scan results with hashed Redis keys and TTL controls',
      content: 'Analyze, AI scan, and malware scan responses are cached with configurable TTLs to reduce repeated API calls and improve response time for popular repositories.',
      videoSrc: null,
      imageSrc: '/images/pawel-czerwinski-8uZPynIu-rQ-unsplash-scaled.webp',
      icon: GraduationCap,
      href: '/platform'
    },
    {
      id: 'auth',
      title: 'JWT Authentication',
      preTitle: 'Access Control Module',
      description: 'Protect scanner workflows with register/login and Bearer token middleware',
      content: 'GitGuard backend issues JWT tokens on login and verifies Bearer headers in middleware so only authenticated users can access protected security workflows.',
      videoSrc: null,
      imageSrc: '/images/pawel-czerwinski-8uZPynIu-rQ-unsplash-scaled.webp',
      icon: Lock,
      href: '/platform'
    }
  ]

  const contentVariants = {
    hidden: { opacity: 0, x: 50 },
    visible: { opacity: 1, x: 0 },
    exit: { opacity: 0, x: -50 }
  }

  return (
    <section className="py-16 bg-linear-to-b from-[#0d172a] via-[#0e1a2e] to-[#0b1424]">
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
            <h2 className="px-6 text-2xl font-semibold uppercase tracking-wider text-[#c7dcf6]">
              Backend capabilities
            </h2>
            <div className="h-px bg-white/20 w-20"></div>
          </div>
          <h3 className="text-3xl md:text-4xl font-bold text-white max-w-4xl mx-auto">
            From repository intake to malware verdict, each stage is explicit and auditable
          </h3>
        </motion.div>

        {/* Tab Navigation */}
        <motion.div
          className="flex flex-wrap justify-center gap-4 mb-12"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          viewport={{ once: true }}
        >
          {tabs.map((tab, index) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(index)}
              className={`px-6 py-3 rounded-lg font-medium transition-all duration-300 ${
                activeTab === index
                  ? 'bg-linear-to-r from-[#1f6feb] to-[#58a6ff] text-white shadow-[0_10px_22px_rgba(31,111,235,0.35)]'
                  : 'bg-white/8 text-[#c9d1d9] border border-white/10 hover:bg-white/14 hover:text-white'
              }`}
            >
              {tab.title}
            </button>
          ))}
        </motion.div>

        {/* Tab Content */}
        <div className="max-w-6xl mx-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              variants={contentVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
              transition={{ duration: 0.4 }}
              className="grid md:grid-cols-2 gap-12 items-center"
            >
              {/* Left Content */}
              <div className="space-y-6">
                <div className="text-sm font-semibold text-[#8db8f6] uppercase tracking-wider">
                  {tabs[activeTab].preTitle}
                </div>
                
                <h3 className="text-2xl font-bold text-white">
                  {tabs[activeTab].description}
                </h3>
                
                <p className="text-[#a9c0dd] leading-relaxed">
                  {tabs[activeTab].content}
                </p>
                
                <Button
                  href={tabs[activeTab].href}
                  variant="primary"
                  size="medium"
                >
                  {tabs[activeTab].id === 'platform' ? 'Discover the platform' : `Discover ${tabs[activeTab].title}`}
                </Button>
              </div>

              {/* Right Content - Video/Image */}
              <div className="relative">
                <div className="rounded-2xl border border-white/10 bg-linear-to-br from-[#11213a] to-[#1a2f4d] p-8 shadow-[0_18px_35px_rgba(3,10,22,0.38)]">
                  {tabs[activeTab].videoSrc ? (
                    <div className="relative rounded-xl overflow-hidden bg-black">
                      <video
                        className="w-full h-auto rounded-xl"
                        autoPlay
                        muted
                        loop
                        playsInline
                        onError={(e) => {
                          const target = e.target as HTMLVideoElement;
                          target.style.display = 'none';
                          const parent = target.parentElement;
                          if (parent) {
                            parent.innerHTML = `<div class="w-full h-48 bg-linear-to-br from-[#11213a] to-[#1a2f4d] rounded-xl flex items-center justify-center text-[#d3e5fb]">Video Demo</div>`;
                          }
                        }}
                      >
                        <source src={tabs[activeTab].videoSrc} type="video/mp4" />
                        {/* <source src={tabs[activeTab].videoSrc?.replace('.mp4', '.webm')} type="video/webm" /> */}
                      </video>
                      
                    </div>
                  ) : (
                    <div className="rounded-xl overflow-hidden">
                      <Image
                        src={tabs[activeTab].imageSrc}
                        alt={tabs[activeTab].title}
                        width={1280}
                        height={720}
                        className="w-full h-auto rounded-xl"
                        onError={(e) => {
                          const target = e.target as HTMLImageElement;
                          target.style.display = 'none';
                          const parent = target.parentElement;
                          if (parent) {
                            parent.innerHTML = `<div class="w-full h-48 bg-linear-to-br from-[#11213a] to-[#1a2f4d] rounded-xl flex items-center justify-center text-[#d3e5fb]">${tabs[activeTab].title}</div>`;
                          }
                        }}
                      />
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </section>
  )
}

export default PlatformTabs
