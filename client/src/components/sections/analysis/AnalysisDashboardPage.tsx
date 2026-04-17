'use client'

import React, { useMemo, useState } from 'react'
import Header from '@/components/layout/Header'
import Footer from '@/components/layout/Footer'
import Button from '@/components/ui/Button'

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

  const prettyRawOutput = useMemo(() => JSON.stringify(config.rawOutput, null, 2), [config.rawOutput])

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
    <div className="min-h-screen bg-white">
      <Header />

      <main className="py-16 bg-gradient-to-b from-white to-gray-50">
        <section className="container mx-auto px-4">
          <div className="max-w-6xl mx-auto space-y-8">
            <div className="text-center">
              <div className="inline-flex items-center justify-center mb-6">
                <div className="h-px bg-gray-300 w-20"></div>
                <h1 className="px-6 text-2xl font-semibold uppercase tracking-wider text-gray-900">
                  {config.sectionLabel}
                </h1>
                <div className="h-px bg-gray-300 w-20"></div>
              </div>
              <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">{config.title}</h2>
              <p className="text-lg text-gray-600 max-w-3xl mx-auto">{config.subtitle}</p>
            </div>

            <div className="bg-white rounded-2xl shadow-xl p-6 md:p-8 border border-gray-100">
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
                  className="flex-1 rounded-lg border border-gray-300 px-4 py-3 text-gray-700 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
                <Button onClick={handleAnalyze} className="md:w-auto w-full" disabled={isLoading || !repoUrl.trim()}>
                  {config.buttonLabel}
                </Button>
              </div>
            </div>

            {isLoading && (
              <div className="bg-white rounded-2xl shadow-xl p-10 border border-gray-100 flex items-center justify-center">
                <div className="flex items-center gap-4 text-gray-700">
                  <div className="h-8 w-8 rounded-full border-4 border-blue-200 border-t-blue-600 animate-spin"></div>
                  <span className="text-lg font-medium">{config.loadingLabel}</span>
                </div>
              </div>
            )}

            {hasResults && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <article className="bg-white rounded-2xl shadow-xl p-6 border border-gray-100">
                    <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-500 mb-3">
                      {config.scoreCardTitle}
                    </h3>
                    <div className="text-4xl font-bold text-blue-600 mb-2">{config.scoreValue}</div>
                    <p className="text-sm text-gray-600">{config.scoreCaption}</p>
                  </article>

                  {config.statusCard && (
                    <article className="bg-white rounded-2xl shadow-xl p-6 border border-gray-100">
                      <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-500 mb-3">
                        {config.statusCard.title}
                      </h3>
                      <div className={`text-2xl font-bold mb-2 ${config.statusCard.toneClassName ?? 'text-gray-900'}`}>
                        {config.statusCard.value}
                      </div>
                      <p className="text-sm text-gray-600">{config.statusCard.description}</p>
                    </article>
                  )}

                  <article className={`bg-white rounded-2xl shadow-xl p-6 border border-gray-100 ${config.statusCard ? '' : 'lg:col-span-2'}`}>
                    <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-500 mb-4">
                      Repository Info
                    </h3>
                    <div className="mb-4">
                      <p className="text-lg font-semibold text-gray-900">{config.repoInfo.name}</p>
                      <p className="text-sm text-gray-600 mt-1">{config.repoInfo.description}</p>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {config.repoInfo.metrics.map((metric) => (
                        <div key={metric.label} className="bg-gray-50 rounded-lg p-3 border border-gray-100">
                          <p className="text-xs uppercase tracking-wide text-gray-500">{metric.label}</p>
                          <p className="text-sm font-semibold text-gray-900 mt-1">{metric.value}</p>
                        </div>
                      ))}
                    </div>
                  </article>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                  <article className="bg-white rounded-2xl shadow-xl p-6 border border-gray-100">
                    <h3 className="text-xl font-semibold text-gray-900 mb-5">{config.distributionTitle}</h3>
                    <div className="space-y-4">
                      {config.distributionMetrics.map((item) => (
                        <div key={item.label}>
                          <div className="flex items-center justify-between text-sm mb-2">
                            <span className="text-gray-700 font-medium">{item.label}</span>
                            <span className="text-gray-600">{item.value}%</span>
                          </div>
                          <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${item.barClassName ?? 'bg-blue-600'}`}
                              style={{ width: `${Math.min(Math.max(item.value, 0), 100)}%` }}
                            ></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className="bg-white rounded-2xl shadow-xl p-6 border border-gray-100">
                    <h3 className="text-xl font-semibold text-gray-900 mb-5">{config.metricsTitle}</h3>
                    <div className="space-y-4">
                      {config.progressMetrics.map((metric) => (
                        <div key={metric.label}>
                          <div className="flex items-center justify-between text-sm mb-2">
                            <span className="text-gray-700 font-medium">{metric.label}</span>
                            <span className="text-gray-600">{metric.value}</span>
                          </div>
                          <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full bg-blue-600"
                              style={{ width: `${Math.min(Math.max(metric.progress, 0), 100)}%` }}
                            ></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>
                </div>

                <article className="bg-white rounded-2xl shadow-xl p-6 border border-gray-100">
                  <h3 className="text-xl font-semibold text-gray-900 mb-3">{config.summaryTitle}</h3>
                  <p className="text-gray-700 leading-relaxed">{config.summaryText}</p>
                </article>

                {config.roadmapItems && config.roadmapItems.length > 0 && (
                  <article className="bg-white rounded-2xl shadow-xl p-6 border border-gray-100">
                    <h3 className="text-xl font-semibold text-gray-900 mb-4">
                      {config.roadmapTitle ?? 'Roadmap'}
                    </h3>
                    <ul className="space-y-3">
                      {config.roadmapItems.map((item) => (
                        <li key={item} className="flex items-start gap-3 text-gray-700">
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
              </div>
            )}
          </div>
        </section>
      </main>

      <Footer />
    </div>
  )
}

export default AnalysisDashboardPage
