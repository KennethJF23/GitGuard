'use client'

import React from 'react'
import Image from 'next/image'
import { motion } from 'framer-motion'
import { BrainCircuit, Radar, ShieldCheck } from 'lucide-react'

type FeatureItem = {
  title: string
  subtitle: string
  description: string
  bulletPoints: string[]
  icon: React.ComponentType<{ className?: string }>
  imageSrc: string
  imageAlt: string
}

const featureItems: FeatureItem[] = [
  {
    title: 'Human Repository Analysis',
    subtitle: 'Context-first security review',
    description:
      'Analyze repository structure, activity signals, and documentation quality before you approve any third-party code.',
    bulletPoints: ['Score breakdown by signal type', 'Repository momentum tracking', 'License guidance with actionable points'],
    icon: BrainCircuit,
    imageSrc: '/images/human%20repo.png',
    imageAlt: 'Human analysis dashboard preview',
  },
  {
    title: 'AI-Assisted Intelligence',
    subtitle: 'Fast triage with explainable outputs',
    description:
      'Generate AI-backed repository insights with compliance indicators and practical recommendations for secure adoption.',
    bulletPoints: ['Readiness and quality indicators', 'Policy and compliance summaries', 'Structured raw output for audit trails'],
    icon: Radar,
    imageSrc: '/images/aiassist.png',
    imageAlt: 'AI analysis insights panel preview',
  },
  {
    title: 'Malware Detection Pipeline',
    subtitle: 'Deterministic threat classification',
    description:
      'Scan source archives, detect suspicious patterns, and classify risk with transparent rules you can verify.',
    bulletPoints: ['Keyword and pattern matching', 'Severity-based risk grouping', 'Focused review recommendations'],
    icon: ShieldCheck,
    imageSrc: '/images/malware.png',
    imageAlt: 'Malware detection findings preview',
  },
]

const FeaturesShowcase: React.FC = () => {
  return (
    <section className="bg-linear-to-b from-[#0a1426] via-[#0f1b2f] to-[#0d172a] py-18 md:py-22">
      <div className="container mx-auto px-4">
        <motion.div
          className="mx-auto mb-14 max-w-3xl text-center"
          initial={{ opacity: 0, y: 18 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          viewport={{ once: true }}
        >
          <span className="inline-flex rounded-full border border-[#24476f] bg-[#13263f] px-3 py-1 text-xs font-semibold uppercase tracking-[0.16em] text-[#93c5fd]">
            GitGuard Features
          </span>
          <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-white md:text-4xl">
            Everything you need to evaluate repository risk with confidence
          </h2>
          <p className="mt-4 text-base leading-relaxed text-[#9fb5d4] md:text-lg">
            From manual review to AI-driven insights and malware detection, GitGuard gives you clear, auditable signals before code enters your stack.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {featureItems.map((feature, index) => {
            const Icon = feature.icon

            return (
              <motion.article
                key={feature.title}
                className="group overflow-hidden rounded-2xl border border-white/10 bg-[#0f2138] shadow-[0_20px_45px_rgba(3,10,22,0.42)]"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.45, delay: index * 0.08 }}
                viewport={{ once: true }}
              >
                <div className="relative h-44 w-full overflow-hidden">
                  <Image
                    src={feature.imageSrc}
                    alt={feature.imageAlt}
                    fill
                    className="object-cover transition-transform duration-500 group-hover:scale-[1.06]"
                    sizes="(max-width: 1024px) 100vw, 33vw"
                  />
                  <div className="absolute inset-0 bg-linear-to-t from-[#02060d]/75 via-[#0a1424]/35 to-transparent" />
                  <div className="absolute left-4 top-4 inline-flex h-10 w-10 items-center justify-center rounded-lg border border-white/30 bg-white/15 text-white backdrop-blur-sm">
                    <Icon className="h-5 w-5" />
                  </div>
                </div>

                <div className="space-y-4 p-6">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#93c5fd]">{feature.subtitle}</p>
                    <h3 className="mt-2 text-xl font-bold text-white">{feature.title}</h3>
                  </div>

                  <p className="text-sm leading-6 text-[#b8cce5]">{feature.description}</p>

                  <ul className="space-y-2">
                    {feature.bulletPoints.map((point) => (
                      <li key={point} className="flex items-start gap-2 text-sm text-[#d9e8f7]">
                        <span className="mt-2 inline-block h-1.5 w-1.5 rounded-full bg-blue-600" />
                        <span>{point}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </motion.article>
            )
          })}
        </div>
      </div>
    </section>
  )
}

export default FeaturesShowcase
