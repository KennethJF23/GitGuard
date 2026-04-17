'use client'

import React, { useMemo, useState } from 'react'
import Header from '@/components/layout/Header'
import Footer from '@/components/layout/Footer'
import Button from '@/components/ui/Button'
import { motion } from 'framer-motion'

type ProgressMetric = {
  label: string
  value: string
  progress: number
}

type DistributionMetric = {
  label: string
  value: number
  barClassName?: string
}

type RepoMetric = {
  label: string
  value: string
}

type StatusCard = {
  title: string
  value: string
  description: string
  toneClassName?: string
}

type RepoInfo = {
  name: string
  description: string
  metrics: RepoMetric[]
}

type AnalysisDashboardConfig = {
  theme?: 'light' | 'dark'
  hideHeader?: boolean
  sectionLabel: string
  title: string
  subtitle: string
  buttonLabel: string
  loadingLabel: string
  scoreCardTitle: string
  scoreValue: string
  scoreCaption: string
  repoInfo: RepoInfo
  distributionTitle: string
  distributionMetrics: DistributionMetric[]
  metricsTitle: string
  progressMetrics: ProgressMetric[]
  summaryTitle: string
  summaryText: string
  roadmapTitle?: string
  roadmapItems?: string[]
  statusCard?: StatusCard
  rawOutputTitle: string
  rawOutput: Record<string, unknown>
}

type AnalysisDashboardPageProps = {
  config: AnalysisDashboardConfig
}

const AnalysisDashboardPage: React.FC<AnalysisDashboardPageProps> = ({ config }) => {
  const [repoUrl, setRepoUrl] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [hasResults, setHasResults] = useState(false)
  const isDark = config.theme === 'dark'

  const normalizedDistributionMetrics = config.distributionMetrics.map((item) => ({
    ...item,
    value: Math.min(Math.max(item.value, 0), 100),
  }))
  const normalizedProgressMetrics = config.progressMetrics.map((item) => ({
    ...item,
    progress: Math.min(Math.max(item.progress, 0), 100),
  }))

  const licenseMetric = config.repoInfo.metrics.find((metric) => /license/i.test(metric.label))
  const hasLicense = licenseMetric
    ? !/none|missing|unknown|n\/a|no/i.test(String(licenseMetric.value || '').toLowerCase())
    : false
  const averageReadiness =
    normalizedProgressMetrics.length > 0
      ? Math.round(
          normalizedProgressMetrics.reduce((sum, metric) => sum + metric.progress, 0) /
            normalizedProgressMetrics.length,
        )
      : 0
  const strongestSignal =
    normalizedDistributionMetrics.length > 0
      ? [...normalizedDistributionMetrics].sort((a, b) => b.value - a.value)[0]
      : null

  const lineChartPoints = normalizedProgressMetrics
    .map((metric, index) => {
      const x = normalizedProgressMetrics.length > 1 ? (index / (normalizedProgressMetrics.length - 1)) * 100 : 50
      const y = 100 - metric.progress
      return `${x},${y}`
    })
    .join(' ')

  const prettyRawOutput = useMemo(() => JSON.stringify(config.rawOutput, null, 2), [config.rawOutput])
  const currentRepoUrl = repoUrl.trim()
  const displayedRepoName = currentRepoUrl || config.repoInfo.name
  const displayedRepoDescription = currentRepoUrl
    ? `Analysis generated for: ${currentRepoUrl}`
    : config.repoInfo.description
  const resultCardClass = isDark
    ? 'rounded-2xl border border-white/10 bg-white/5 shadow-xl transition-all duration-300 hover:-translate-y-1 hover:border-cyan-300/40 hover:shadow-[0_0_0_1px_rgba(125,211,252,0.28),0_0_24px_rgba(56,189,248,0.22),0_16px_30px_rgba(2,6,23,0.55)]'
    : 'rounded-2xl border border-gray-100 bg-white shadow-xl'
  const resultPanelClass = isDark
    ? 'space-y-6 rounded-3xl border border-white/10 bg-linear-to-b from-white/[0.05] via-white/[0.025] to-transparent p-4 md:p-6 backdrop-blur-sm'
    : 'space-y-6'

  const handleAnalyze = () => {
    if (!repoUrl.trim()) {
      return
    }

    setIsLoading(true)
    setHasResults(false)

    window.setTimeout(() => {
      setIsLoading(false)
      setHasResults(true)
    }, 1200)
  }

  return (
    <div className={isDark ? 'min-h-screen bg-linear-to-br from-blue-950 via-slate-950 to-black text-white' : 'min-h-screen bg-white'}>
      {!config.hideHeader && <Header />}

      <main className={isDark ? 'py-16' : 'py-16 bg-linear-to-b from-white to-gray-50'}>
        <section className="container mx-auto px-4">
          <div className="max-w-6xl mx-auto space-y-8">
            <div className="text-center">
              <div className="inline-flex items-center justify-center mb-6">
                <div className={isDark ? 'h-px bg-white/20 w-20' : 'h-px bg-gray-300 w-20'}></div>
                <h1 className={isDark ? 'px-6 text-2xl font-semibold uppercase tracking-wider text-blue-200' : 'px-6 text-2xl font-semibold uppercase tracking-wider text-gray-900'}>
                  {config.sectionLabel}
                </h1>
                <div className={isDark ? 'h-px bg-white/20 w-20' : 'h-px bg-gray-300 w-20'}></div>
              </div>
              <h2 className={isDark ? 'text-3xl md:text-4xl font-bold text-white mb-4' : 'text-3xl md:text-4xl font-bold text-gray-900 mb-4'}>{config.title}</h2>
              <p className={isDark ? 'text-lg text-blue-100 max-w-3xl mx-auto' : 'text-lg text-gray-600 max-w-3xl mx-auto'}>{config.subtitle}</p>
            </div>

            <div className={isDark ? 'bg-white/5 rounded-2xl shadow-xl p-6 md:p-8 border border-white/10 backdrop-blur-md' : 'bg-white rounded-2xl shadow-xl p-6 md:p-8 border border-gray-100'}>
              <div className="flex flex-col md:flex-row gap-4">
                <input
                  type="url"
                  value={repoUrl}
                  onChange={(event) => setRepoUrl(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') {
                      handleAnalyze()
                    }
                  }}
                  placeholder="https://github.com/owner/repository"
                  className={isDark ? 'flex-1 rounded-lg border border-white/20 bg-black/30 px-4 py-3 text-white placeholder:text-blue-200/70 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-400' : 'flex-1 rounded-lg border border-gray-300 px-4 py-3 text-gray-700 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600'}
                />
                <Button onClick={handleAnalyze} className="md:w-auto w-full" disabled={isLoading || !repoUrl.trim()}>
                  {config.buttonLabel}
                </Button>
              </div>
            </div>

            {isLoading && (
              <div className={isDark ? 'bg-white/5 rounded-2xl shadow-xl p-10 border border-white/10 flex items-center justify-center' : 'bg-white rounded-2xl shadow-xl p-10 border border-gray-100 flex items-center justify-center'}>
                <div className={isDark ? 'flex items-center gap-4 text-blue-100' : 'flex items-center gap-4 text-gray-700'}>
                  <div className="h-8 w-8 rounded-full border-4 border-blue-200 border-t-blue-600 animate-spin"></div>
                  <span className="text-lg font-medium">{config.loadingLabel}</span>
                </div>
              </div>
            )}

            {hasResults && (
              <motion.div
                className={resultPanelClass}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.45 }}
              >
                <div className={isDark ? 'rounded-xl border border-cyan-300/20 bg-linear-to-r from-cyan-400/10 via-blue-400/5 to-transparent px-4 py-3 text-xs uppercase tracking-wider text-cyan-100' : 'rounded-xl border border-blue-100 bg-blue-50 px-4 py-3 text-xs uppercase tracking-wider text-blue-700'}>
                  Analysis complete. Hover cards to inspect signals and metrics.
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <motion.article
                    initial={{ opacity: 0, y: 14 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.35 }}
                    className={`${resultCardClass} p-6`}
                  >
                    <h3 className={isDark ? 'text-sm font-semibold uppercase tracking-wide text-blue-200 mb-3' : 'text-sm font-semibold uppercase tracking-wide text-gray-500 mb-3'}>
                      {config.scoreCardTitle}
                    </h3>
                    <div className="text-4xl font-bold text-blue-600 mb-2">{config.scoreValue}</div>
                    <p className={isDark ? 'text-sm text-blue-100' : 'text-sm text-gray-600'}>{config.scoreCaption}</p>
                  </motion.article>

                  {config.statusCard && (
                    <motion.article
                      initial={{ opacity: 0, y: 14 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.35, delay: 0.06 }}
                      className={`${resultCardClass} p-6`}
                    >
                      <h3 className={isDark ? 'text-sm font-semibold uppercase tracking-wide text-blue-200 mb-3' : 'text-sm font-semibold uppercase tracking-wide text-gray-500 mb-3'}>
                        {config.statusCard.title}
                      </h3>
                      <div className={`text-2xl font-bold mb-2 ${config.statusCard.toneClassName ?? 'text-gray-900'}`}>
                        {config.statusCard.value}
                      </div>
                      <p className={isDark ? 'text-sm text-blue-100' : 'text-sm text-gray-600'}>{config.statusCard.description}</p>
                    </motion.article>
                  )}

                  <motion.article
                    initial={{ opacity: 0, y: 14 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.35, delay: 0.12 }}
                    className={`${resultCardClass} p-6 ${config.statusCard ? '' : 'lg:col-span-2'}`}
                  >
                    <h3 className={isDark ? 'text-sm font-semibold uppercase tracking-wide text-blue-200 mb-4' : 'text-sm font-semibold uppercase tracking-wide text-gray-500 mb-4'}>
                      Repository Info
                    </h3>
                    <div className="mb-4">
                      <p className={isDark ? 'text-lg font-semibold text-white break-all' : 'text-lg font-semibold text-gray-900 break-all'}>{displayedRepoName}</p>
                      <p className={isDark ? 'text-sm text-blue-100 mt-1 break-all' : 'text-sm text-gray-600 mt-1 break-all'}>{displayedRepoDescription}</p>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {config.repoInfo.metrics.map((metric) => (
                        <div key={metric.label} className={isDark ? 'bg-black/20 rounded-lg p-3 border border-white/10' : 'bg-gray-50 rounded-lg p-3 border border-gray-100'}>
                          <p className={isDark ? 'text-xs uppercase tracking-wide text-blue-200' : 'text-xs uppercase tracking-wide text-gray-500'}>{metric.label}</p>
                          <p className={isDark ? 'text-sm font-semibold text-white mt-1' : 'text-sm font-semibold text-gray-900 mt-1'}>{metric.value}</p>
                        </div>
                      ))}
                    </div>
                  </motion.article>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <article className={`${resultCardClass} p-5`}>
                    <p className={isDark ? 'text-xs uppercase tracking-wide text-blue-200' : 'text-xs uppercase tracking-wide text-gray-500'}>License Status</p>
                    <p className={isDark ? `mt-2 text-2xl font-bold ${hasLicense ? 'text-emerald-300' : 'text-red-300'}` : `mt-2 text-2xl font-bold ${hasLicense ? 'text-emerald-600' : 'text-red-600'}`}>
                      {hasLicense ? 'HAS LICENSE' : 'NO LICENSE'}
                    </p>
                    <p className={isDark ? 'mt-2 text-sm text-blue-100' : 'mt-2 text-sm text-gray-600'}>
                      {licenseMetric ? `Detected: ${licenseMetric.value}` : 'No license field was found in repository metrics.'}
                    </p>
                  </article>

                  <article className={`${resultCardClass} p-5`}>
                    <p className={isDark ? 'text-xs uppercase tracking-wide text-blue-200' : 'text-xs uppercase tracking-wide text-gray-500'}>Average Metric Score</p>
                    <p className="mt-2 text-2xl font-bold text-blue-400">{averageReadiness}%</p>
                    <p className={isDark ? 'mt-2 text-sm text-blue-100' : 'mt-2 text-sm text-gray-600'}>
                      Mean score across readiness metrics in this AI analysis.
                    </p>
                  </article>

                  <article className={`${resultCardClass} p-5`}>
                    <p className={isDark ? 'text-xs uppercase tracking-wide text-blue-200' : 'text-xs uppercase tracking-wide text-gray-500'}>Strongest Signal</p>
                    <p className="mt-2 text-2xl font-bold text-blue-400">{strongestSignal ? strongestSignal.label : 'N/A'}</p>
                    <p className={isDark ? 'mt-2 text-sm text-blue-100' : 'mt-2 text-sm text-gray-600'}>
                      {strongestSignal ? `${strongestSignal.value}% contribution in distribution analysis.` : 'No distribution metrics available.'}
                    </p>
                  </article>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'text-xl font-semibold text-white mb-5' : 'text-xl font-semibold text-gray-900 mb-5'}>{config.distributionTitle}</h3>
                    <div className="space-y-4">
                      {normalizedDistributionMetrics.map((item) => (
                        <div key={item.label}>
                          <div className="flex items-center justify-between text-sm mb-2">
                            <span className={isDark ? 'text-blue-100 font-medium' : 'text-gray-700 font-medium'}>{item.label}</span>
                            <span className={isDark ? 'text-blue-200' : 'text-gray-600'}>{item.value}%</span>
                          </div>
                          <div className={isDark ? 'h-2 bg-white/10 rounded-full overflow-hidden' : 'h-2 bg-gray-200 rounded-full overflow-hidden'}>
                            <div
                              className={`h-full rounded-full ${item.barClassName ?? 'bg-blue-600'}`}
                              style={{ width: `${item.value}%` }}
                            ></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'text-xl font-semibold text-white mb-5' : 'text-xl font-semibold text-gray-900 mb-5'}>{config.metricsTitle}</h3>
                    <div className="space-y-4">
                      {normalizedProgressMetrics.map((metric) => (
                        <div key={metric.label}>
                          <div className="flex items-center justify-between text-sm mb-2">
                            <span className={isDark ? 'text-blue-100 font-medium' : 'text-gray-700 font-medium'}>{metric.label}</span>
                            <span className={isDark ? 'text-blue-200' : 'text-gray-600'}>{metric.value}</span>
                          </div>
                          <div className={isDark ? 'h-2 bg-white/10 rounded-full overflow-hidden' : 'h-2 bg-gray-200 rounded-full overflow-hidden'}>
                            <div
                              className="h-full rounded-full bg-blue-600"
                              style={{ width: `${metric.progress}%` }}
                            ></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'text-xl font-semibold text-white mb-5' : 'text-xl font-semibold text-gray-900 mb-5'}>Bar Chart: Repository Composition</h3>
                    <div className={isDark ? 'rounded-xl bg-black/20 border border-white/10 p-4' : 'rounded-xl bg-gray-50 border border-gray-100 p-4'}>
                      <div className="flex items-end gap-3 h-52">
                      {normalizedDistributionMetrics.map((item) => (
                        <div key={item.label} className="flex-1 h-full flex flex-col items-center justify-end gap-2">
                          <p className={isDark ? 'text-xs font-semibold text-blue-200' : 'text-xs font-semibold text-gray-700'}>
                            {item.value}%
                          </p>
                          <motion.div
                            initial={{ height: 0, opacity: 0.6 }}
                            animate={{ height: Math.max((item.value / 100) * 150, 12), opacity: 1 }}
                            transition={{ duration: 0.5 }}
                            className={isDark ? 'w-full rounded-t-md bg-blue-500/80 border border-blue-300/30' : 'w-full rounded-t-md bg-blue-500'}
                          />
                          <p className={isDark ? 'text-[11px] text-blue-100 text-center' : 'text-[11px] text-gray-700 text-center'}>{item.label}</p>
                        </div>
                      ))}
                      </div>
                    </div>
                  </article>

                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'text-xl font-semibold text-white mb-5' : 'text-xl font-semibold text-gray-900 mb-5'}>Trend Chart: Readiness Metrics</h3>
                    <div className={isDark ? 'rounded-xl bg-black/20 border border-white/10 p-4' : 'rounded-xl bg-gray-50 border border-gray-100 p-4'}>
                      <svg viewBox="0 0 100 100" className="w-full h-44">
                        <line x1="8" y1="10" x2="8" y2="90" stroke={isDark ? '#334155' : '#cbd5e1'} strokeWidth="0.8" />
                        <line x1="8" y1="90" x2="92" y2="90" stroke={isDark ? '#334155' : '#cbd5e1'} strokeWidth="0.8" />
                        <polyline
                          fill="none"
                          stroke={isDark ? '#7dd3fc' : '#2563eb'}
                          strokeWidth="2.5"
                          points={normalizedProgressMetrics
                            .map((metric, index) => {
                              const x = normalizedProgressMetrics.length > 1 ? 10 + (index / (normalizedProgressMetrics.length - 1)) * 80 : 50
                              const y = 90 - (metric.progress / 100) * 80
                              return `${x},${y}`
                            })
                            .join(' ')}
                        />
                        {normalizedProgressMetrics.map((metric, index) => {
                          const x = normalizedProgressMetrics.length > 1 ? 10 + (index / (normalizedProgressMetrics.length - 1)) * 80 : 50
                          const y = 90 - (metric.progress / 100) * 80
                          return (
                            <g key={metric.label}>
                              <circle cx={x} cy={y} r="2" fill={isDark ? '#bfdbfe' : '#1d4ed8'} />
                              <text
                                x={x}
                                y={Math.max(y - 4, 8)}
                                textAnchor="middle"
                                fontSize="4"
                                fill={isDark ? '#bfdbfe' : '#1d4ed8'}
                                fontWeight="700"
                              >
                                {metric.progress}%
                              </text>
                            </g>
                          )
                        })}
                      </svg>
                      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                        {normalizedProgressMetrics.map((metric) => (
                          <div key={`label-${metric.label}`} className={isDark ? 'rounded-lg border border-white/10 bg-black/20 px-2 py-1 text-[11px] text-blue-100' : 'rounded-lg border border-gray-200 bg-white px-2 py-1 text-[11px] text-gray-700'}>
                            <span className="font-semibold">{metric.label}:</span> {metric.progress}%
                          </div>
                        ))}
                      </div>
                    </div>
                  </article>
                </div>

                <article className={`${resultCardClass} p-6`}>
                  <h3 className={isDark ? 'text-xl font-semibold text-white mb-3' : 'text-xl font-semibold text-gray-900 mb-3'}>{config.summaryTitle}</h3>
                  <p className={isDark ? 'text-blue-100 leading-relaxed' : 'text-gray-700 leading-relaxed'}>{config.summaryText}</p>
                </article>

                {config.roadmapItems && config.roadmapItems.length > 0 && (
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'text-xl font-semibold text-white mb-4' : 'text-xl font-semibold text-gray-900 mb-4'}>
                      {config.roadmapTitle ?? 'Roadmap'}
                    </h3>
                    <ul className="space-y-3">
                      {config.roadmapItems.map((item) => (
                        <li key={item} className={isDark ? 'flex items-start gap-3 text-blue-100' : 'flex items-start gap-3 text-gray-700'}>
                          <span className="h-6 w-6 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-sm font-semibold">
                            ✓
                          </span>
                          <span className="pt-0.5">{item}</span>
                        </li>
                      ))}
                    </ul>
                  </article>
                )}

                <article className="bg-gray-900 rounded-2xl shadow-xl p-6 border border-gray-800">
                  <h3 className="text-lg font-semibold text-white mb-4">{config.rawOutputTitle}</h3>
                  <pre className="text-xs md:text-sm text-gray-100 overflow-x-auto whitespace-pre-wrap">{prettyRawOutput}</pre>
                </article>
              </motion.div>
            )}
          </div>
        </section>
      </main>

      <Footer />
    </div>
  )
}

export default AnalysisDashboardPage
