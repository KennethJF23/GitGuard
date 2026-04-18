'use client'

import React, { useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import Header from '@/components/layout/Header'
import Footer from '@/components/layout/Footer'
import Button from '@/components/ui/Button'
import { clearAuthSession, getAuthToken } from '@/lib/authSession'

type DashboardMode = 'human' | 'ai' | 'malware'

type DistributionMetric = {
  label: string
  value: number
  barClassName?: string
}

type ProgressMetric = {
  label: string
  progress: number
  value: string
}

type RepoMetric = {
  label: string
  value: string
}

type LicenseDetection = {
  license: string
  confidence?: string
  source?: string
  riskImpact?: string
}

type MalwareTechnicalDetail = {
  category: string
  matchedPatterns: string[]
  riskContribution: number
}

type MalwareExplanation = {
  summary?: string
  keyFindings?: string[]
  technicalDetails?: MalwareTechnicalDetail[]
  verdictReason?: string
  combinations?: string[]
}

type AIRecommendation = {
  priority: 'HIGH' | 'MEDIUM' | 'LOW' | string
  action: string
}

type AIInsights = {
  summary?: string
  strengths?: string[]
  risks?: string[]
  trustScoreReasoning?: string
  recommendations?: AIRecommendation[]
}

type TrustReport = {
  trustScore?: number
  breakdown?: {
    codeSafety?: number
    documentation?: number
    license?: number
    activity?: number
  }
  verdict?: string
  explanation?: string
}

type DashboardResult = {
  score: number
  scoreText: string
  scoreCaption: string
  statusTitle: string
  statusValue: string
  statusDescription: string
  repoName: string
  repoDescription: string
  repoMetrics: RepoMetric[]
  distributionMetrics: DistributionMetric[]
  progressMetrics: ProgressMetric[]
  summaryText: string
  roadmapItems: string[]
  licenseDetection?: LicenseDetection | null
  malwareExplanation?: MalwareExplanation | null
  aiInsights?: AIInsights | null
  trustReport?: TrustReport | null
  rawOutput: Record<string, unknown>
}

type AnalysisDashboardConfig = {
  mode: DashboardMode
  sectionLabel: string
  title: string
  subtitle: string
  buttonLabel: string
  loadingLabel: string
}

type AnalysisDashboardPageProps = {
  config: AnalysisDashboardConfig
}

type GenericResponse = Record<string, unknown>

type MalwareMatch = {
  category?: string
  matchedField?: string
  pattern?: string
  weight?: number
}

const LOADING_STEPS_BY_MODE: Record<DashboardMode, string[]> = {
  human: ['Validating repository URL', 'Collecting repository metadata', 'Computing human-readability scores', 'Preparing final dashboard'],
  ai: ['Validating repository URL', 'Collecting metadata and README', 'Generating local explanation summary', 'Preparing final dashboard'],
  malware: ['Validating repository URL', 'Downloading repository snapshot', 'Running keyword + AST malware scan', 'Preparing final dashboard'],
}

function safeNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function clamp(value: number, min = 0, max = 100): number {
  return Math.min(max, Math.max(min, value))
}

function toTitle(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (m) => m.toUpperCase())
}

function formatPercent(value: number): string {
  return `${Math.round(clamp(value))}%`
}

function isValidGithubRepositoryUrl(input: string): boolean {
  const value = String(input || '').trim()
  if (!value) return false

  if (!/^https?:\/\//i.test(value)) {
    return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value.replace(/^github\.com\//i, ''))
  }

  try {
    const parsed = new URL(value)
    if (!/^(www\.)?github\.com$/i.test(parsed.hostname)) return false
    const segments = parsed.pathname.split('/').filter(Boolean)
    return segments.length >= 2
  } catch {
    return false
  }
}

function extractRoadmapFromText(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^[-*]\s+|^\d+[.)]\s+/.test(line))
    .map((line) => line.replace(/^[-*]\s+/, '').replace(/^\d+[.)]\s+/, '').trim())
    .filter(Boolean)
    .slice(0, 6)
}

function computeAiScore(snapshot: GenericResponse | undefined): number {
  const readme = (snapshot?.readme as GenericResponse | undefined) || {}
  const tooling = (snapshot?.tooling as GenericResponse | undefined) || {}

  const score =
    (readme.present ? 16 : 0) +
    (readme.hasInstall ? 10 : 0) +
    (readme.hasUsage ? 10 : 0) +
    (readme.hasBadges ? 6 : 0) +
    (readme.hasScreenshots ? 6 : 0) +
    (tooling.hasGitHubActions ? 14 : 0) +
    (tooling.hasDependabot ? 12 : 0) +
    (tooling.hasTestsDir ? 12 : 0) +
    (tooling.hasEslint ? 7 : 0) +
    (tooling.hasPrettier ? 7 : 0)

  return clamp(score)
}

function buildHumanResult(payload: GenericResponse): DashboardResult {
  const repo = (payload.repo as GenericResponse | undefined) || {}
  const scoreObj = (payload.score as GenericResponse | undefined) || {}
  const snapshot = (payload.snapshot as GenericResponse | undefined) || {}
  const git = (snapshot.git as GenericResponse | undefined) || {}
  const readme = (snapshot.readme as GenericResponse | undefined) || {}
  const files = (snapshot.files as GenericResponse | undefined) || {}

  const score = clamp(safeNumber(scoreObj.total, safeNumber(scoreObj.value, 0)))
  const breakdown = Array.isArray(scoreObj.breakdown) ? scoreObj.breakdown : []
  const distributionMetrics: DistributionMetric[] = breakdown
    .map((item) => {
      const row = (item as GenericResponse) || {}
      const max = Math.max(1, safeNumber(row.max, 1))
      const raw = safeNumber(row.score, 0)
      return {
        label: String(row.label || row.key || 'Signal'),
        value: clamp((raw / max) * 100),
      }
    })
    .slice(0, 6)

  const commitsLast90 = safeNumber(git.commitsLast90Days, 0)
  const activeDays = safeNumber(git.activeCommitDaysLast90Days, 0)
  const conventionalRate = safeNumber(git.conventionalCommitRate, 0)

  const progressMetrics: ProgressMetric[] = [
    {
      label: 'Commit Activity (90d)',
      progress: clamp((commitsLast90 / 90) * 100),
      value: String(commitsLast90),
    },
    {
      label: 'Active Commit Days',
      progress: clamp((activeDays / 90) * 100),
      value: `${activeDays} / 90`,
    },
    {
      label: 'Conventional Commit Rate',
      progress: clamp(conventionalRate * 100),
      value: formatPercent(conventionalRate * 100),
    },
    {
      label: 'README Completeness',
      progress: clamp(
        (readme.present ? 40 : 0) + (readme.hasInstall ? 20 : 0) + (readme.hasUsage ? 20 : 0) + (readme.hasBadges ? 10 : 0) + (readme.hasScreenshots ? 10 : 0),
      ),
      value: readme.present ? 'Present' : 'Missing',
    },
  ]

  return {
    score,
    scoreText: `${Math.round(score)} / 100`,
    scoreCaption: String(payload.summary || 'Repository health analysis completed.'),
    statusTitle: 'Risk Card',
    statusValue: String(scoreObj.level || scoreObj.band || 'UNKNOWN').toUpperCase(),
    statusDescription: String(payload.summary || 'No summary generated by backend.'),
    repoName: String(repo.fullName || 'Unknown repository'),
    repoDescription: String(repo.description || 'No repository description returned.'),
    repoMetrics: [
      { label: 'Stars', value: String(safeNumber(repo.stars, 0)) },
      { label: 'Forks', value: String(safeNumber(repo.forks, 0)) },
      { label: 'Open Issues', value: String(safeNumber(repo.openIssues, 0)) },
      { label: 'License', value: String(repo.license || 'N/A') },
      { label: 'Branches', value: String(safeNumber(git.branches, 0)) },
      { label: 'Pull Requests', value: String(safeNumber(git.pullRequests, 0)) },
      { label: 'Contributors', value: String(safeNumber(git.contributors, 0)) },
      { label: 'Commits (90d)', value: String(commitsLast90) },
      { label: 'Files', value: String(safeNumber(files.fileCount, 0)) },
      { label: 'Directories', value: String(safeNumber(files.directoryCount, 0)) },
    ],
    distributionMetrics,
    progressMetrics,
    summaryText: String(payload.summary || 'No summary available.'),
    roadmapItems: Array.isArray(payload.roadmap) ? payload.roadmap.map((v) => String(v)).filter(Boolean).slice(0, 6) : [],
    licenseDetection: ((payload.licenseDetection as LicenseDetection | undefined) || null),
    malwareExplanation: null,
    aiInsights: null,
    trustReport: ((payload.trustReport as TrustReport | undefined) || null),
    rawOutput: payload,
  }
}

function buildAiResult(payload: GenericResponse): DashboardResult {
  const repo = (payload.repo as GenericResponse | undefined) || {}
  const snapshot = (payload.snapshot as GenericResponse | undefined) || {}
  const readme = (snapshot.readme as GenericResponse | undefined) || {}
  const tooling = (snapshot.tooling as GenericResponse | undefined) || {}
  const ai = (payload.ai as GenericResponse | undefined) || {}

  const aiOutput = String(ai.output || '').trim()
  const score = computeAiScore(snapshot)

  const languages = Array.isArray(snapshot.languagesTop) ? snapshot.languagesTop : []
  const distributionMetrics: DistributionMetric[] = languages
    .map((row) => {
      const item = (row as GenericResponse) || {}
      return {
        label: String(item.name || 'Other'),
        value: clamp(safeNumber(item.percent, 0)),
      }
    })
    .slice(0, 6)

  const progressMetrics: ProgressMetric[] = [
    {
      label: 'README Coverage',
      progress: clamp((readme.present ? 40 : 0) + (readme.hasInstall ? 20 : 0) + (readme.hasUsage ? 20 : 0) + (readme.hasBadges ? 10 : 0) + (readme.hasScreenshots ? 10 : 0)),
      value: readme.present ? 'Present' : 'Missing',
    },
    {
      label: 'Tooling Readiness',
      progress: clamp((tooling.hasGitHubActions ? 25 : 0) + (tooling.hasDependabot ? 25 : 0) + (tooling.hasTestsDir ? 25 : 0) + (tooling.hasEslint || tooling.hasPrettier ? 25 : 0)),
      value: 'Derived from repo tooling',
    },
    {
      label: 'CI Security Signal',
      progress: clamp((tooling.hasSecurityPolicy ? 50 : 0) + (tooling.hasDependabot ? 25 : 0) + (tooling.hasGitHubActions ? 25 : 0)),
      value: 'Policy + automation',
    },
    {
      label: 'Documentation Quality',
      progress: clamp(safeNumber(readme.wordCount, 0) / 10),
      value: `${safeNumber(readme.wordCount, 0)} words`,
    },
  ]

  const summaryText = aiOutput || 'AI scan completed. No narrative text returned by backend model output.'
  const roadmapItems = extractRoadmapFromText(aiOutput)
  const aiInsights = ((payload.aiInsights as AIInsights | undefined) || null)

  return {
    score,
    scoreText: `${Math.round(score)} / 100`,
    scoreCaption: 'Computed from README and tooling metadata returned by the backend AI scan.',
    statusTitle: 'AI Model Status',
    statusValue: score >= 75 ? 'HIGH READINESS' : score >= 45 ? 'MODERATE READINESS' : 'LOW READINESS',
    statusDescription: `Model: ${String(ai.model || 'N/A')}`,
    repoName: String(repo.fullName || 'Unknown repository'),
    repoDescription: String(repo.description || 'No repository description returned.'),
    repoMetrics: [
      { label: 'Stars', value: String(safeNumber(repo.stars, 0)) },
      { label: 'Forks', value: String(safeNumber(repo.forks, 0)) },
      { label: 'Open Issues', value: String(safeNumber(repo.openIssues, 0)) },
      { label: 'License', value: String(repo.license || 'N/A') },
    ],
    distributionMetrics,
    progressMetrics,
    summaryText,
    roadmapItems,
    licenseDetection: ((payload.license as LicenseDetection | undefined) || null),
    malwareExplanation: null,
    aiInsights,
    trustReport: ((payload.trustReport as TrustReport | undefined) || null),
    rawOutput: payload,
  }
}

function buildMalwareResult(payload: GenericResponse): DashboardResult {
  const scoreRaw = safeNumber(payload.totalRiskScore, safeNumber(payload.score, 0))
  const score = clamp(safeNumber(payload.normalizedRiskScore, (scoreRaw / 25) * 100))
  const verdict = String(payload.verdict || 'SAFE').toUpperCase()
  const ai = ((payload.ai as GenericResponse | undefined)?.parsed as GenericResponse | undefined) || {}
  const matches = Array.isArray(payload.matches) ? (payload.matches as MalwareMatch[]) : []

  const categories = new Map<string, { indicators: number; weighted: number }>()
  for (const match of matches) {
    const category = String(match.category || 'generic').trim().toLowerCase() || 'generic'
    const current = categories.get(category) || { indicators: 0, weighted: 0 }
    current.indicators += 1
    current.weighted += safeNumber(match.weight, 0)
    categories.set(category, current)
  }

  const distributionMetrics: DistributionMetric[] = Array.from(categories.entries())
    .sort((a, b) => b[1].indicators - a[1].indicators)
    .slice(0, 6)
    .map(([category, values]) => ({
      label: toTitle(category),
      value: clamp((values.indicators / Math.max(1, matches.length)) * 100),
    }))

  const byField = { name: 0, path: 0, content: 0 }
  for (const match of matches) {
    if (match.matchedField === 'name') byField.name += 1
    else if (match.matchedField === 'path') byField.path += 1
    else byField.content += 1
  }

  const totalMatchCount = Math.max(1, matches.length)
  const progressMetrics: ProgressMetric[] = [
    {
      label: 'Name-based Indicators',
      progress: clamp((byField.name / totalMatchCount) * 100),
      value: String(byField.name),
    },
    {
      label: 'Path-based Indicators',
      progress: clamp((byField.path / totalMatchCount) * 100),
      value: String(byField.path),
    },
    {
      label: 'Content-based Indicators',
      progress: clamp((byField.content / totalMatchCount) * 100),
      value: String(byField.content),
    },
    {
      label: 'AI Confidence',
      progress: clamp(safeNumber(ai.confidence, 0) * 100),
      value: formatPercent(safeNumber(ai.confidence, 0) * 100),
    },
  ]

  const confidence = safeNumber(ai.confidence, 0) * 100
  const summaryText =
    String(ai.reasoning || '').trim() ||
    `Backend malware scan identified ${safeNumber(payload.matchCount, 0)} signals with verdict ${verdict}.`

  const aiIndicators = Array.isArray(ai.indicators)
    ? ai.indicators.map((v) => String(v).trim()).filter(Boolean)
    : []
  const topCategoryNames = Array.from(categories.entries())
    .sort((a, b) => b[1].indicators - a[1].indicators)
    .slice(0, 3)
    .map(([name]) => toTitle(name))

  const roadmapItems = [
    ...aiIndicators.map((item) => `Investigate indicator: ${item}`),
    ...topCategoryNames.map((name) => `Prioritize review for ${name} findings`),
  ].slice(0, 6)

  return {
    score,
    scoreText: `${Math.round(score)} / 100`,
    scoreCaption: `Normalized from backend risk score ${scoreRaw.toFixed(2)} returned by malware scan.`,
    statusTitle: 'Verdict Card',
    statusValue: verdict,
    statusDescription: `AI confidence ${formatPercent(confidence)}`,
    repoName: String((payload.input as GenericResponse | undefined)?.url || 'Scanned repository'),
    repoDescription: `Pipeline score ${scoreRaw.toFixed(2)} with ${safeNumber(payload.matchCount, 0)} total matched indicators.`,
    repoMetrics: [
      { label: 'Indicators', value: String(safeNumber(payload.matchCount, 0)) },
      { label: 'Unique Patterns', value: String(new Set(matches.map((m) => m.pattern).filter(Boolean)).size) },
      { label: 'Verdict', value: verdict },
      { label: 'Confidence', value: formatPercent(confidence) },
    ],
    distributionMetrics,
    progressMetrics,
    summaryText,
    roadmapItems,
    licenseDetection: ((payload.licenseDetection as LicenseDetection | undefined) || null),
    malwareExplanation: ((payload.malwareExplanation as MalwareExplanation | undefined) || null),
    aiInsights: null,
    trustReport: ((payload.trustReport as TrustReport | undefined) || null),
    rawOutput: payload,
  }
}

function buildResult(mode: DashboardMode, payload: GenericResponse): DashboardResult {
  if (mode === 'human') return buildHumanResult(payload)
  if (mode === 'ai') return buildAiResult(payload)
  return buildMalwareResult(payload)
}

function endpointForMode(mode: DashboardMode): string {
  if (mode === 'human') return '/api/repo/analyze'
  if (mode === 'ai') return '/api/repo/ai-scan'
  return '/api/repo/malware-pipeline-scan'
}

const AnalysisDashboardPage: React.FC<AnalysisDashboardPageProps> = ({ config }) => {
  const router = useRouter()
  const [repoUrl, setRepoUrl] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [loadingStepIndex, setLoadingStepIndex] = useState(0)
  const [error, setError] = useState('')
  const [result, setResult] = useState<DashboardResult | null>(null)

  const isDark = true
  const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:5000'

  const normalizedDistributionMetrics = (result?.distributionMetrics || []).map((item) => ({
    ...item,
    value: clamp(item.value),
  }))

  const normalizedProgressMetrics = (result?.progressMetrics || []).map((item) => ({
    ...item,
    progress: clamp(item.progress),
  }))

  const licenseMetric = result?.repoMetrics.find((metric) => /license/i.test(metric.label))
  const detectedLicense = result?.licenseDetection?.license || String(licenseMetric?.value || 'MISSING')
  const hasLicense = !/missing|unknown|n\/a|noassertion|none/i.test(String(detectedLicense || '').toLowerCase())

  const averageReadiness =
    normalizedProgressMetrics.length > 0
      ? Math.round(normalizedProgressMetrics.reduce((sum, metric) => sum + metric.progress, 0) / normalizedProgressMetrics.length)
      : 0

  const strongestSignal =
    normalizedDistributionMetrics.length > 0
      ? [...normalizedDistributionMetrics].sort((a, b) => b.value - a.value)[0]
      : null

  const trustBreakdown = result?.trustReport?.breakdown || {}
  const trustMetrics: ProgressMetric[] = [
    { label: 'Code Safety', progress: clamp(safeNumber(trustBreakdown.codeSafety, 0)), value: formatPercent(safeNumber(trustBreakdown.codeSafety, 0)) },
    { label: 'Documentation', progress: clamp(safeNumber(trustBreakdown.documentation, 0)), value: formatPercent(safeNumber(trustBreakdown.documentation, 0)) },
    { label: 'License', progress: clamp(safeNumber(trustBreakdown.license, 0)), value: formatPercent(safeNumber(trustBreakdown.license, 0)) },
    { label: 'Activity', progress: clamp(safeNumber(trustBreakdown.activity, 0)), value: formatPercent(safeNumber(trustBreakdown.activity, 0)) },
  ]

  const aiInsightRecommendations: AIRecommendation[] = Array.isArray(result?.aiInsights?.recommendations)
    ? (result?.aiInsights?.recommendations as AIRecommendation[])
    : []

  const prettyRawOutput = useMemo(
    () => (result ? JSON.stringify(result.rawOutput, null, 2) : ''),
    [result],
  )

  const resultCardClass =
    'rounded-2xl border border-white/10 bg-white/5 shadow-xl transition-all duration-300 hover:-translate-y-1 hover:border-cyan-300/40 hover:shadow-[0_0_0_1px_rgba(125,211,252,0.28),0_0_24px_rgba(56,189,248,0.22),0_16px_30px_rgba(2,6,23,0.55)]'

  const resultPanelClass =
    'space-y-6 rounded-3xl border border-white/10 bg-linear-to-b from-white/[0.05] via-white/[0.025] to-transparent p-4 md:p-6 backdrop-blur-sm'

  const loadingSteps = LOADING_STEPS_BY_MODE[config.mode] || [config.loadingLabel]
  const loadingLabel = loadingSteps[Math.min(loadingStepIndex, Math.max(loadingSteps.length - 1, 0))] || config.loadingLabel

  const handleAnalyze = async () => {
    const normalizedRepoUrl = repoUrl.trim()
    if (!normalizedRepoUrl) {
      setError('Please provide a GitHub repository URL.')
      return
    }

    if (!isValidGithubRepositoryUrl(normalizedRepoUrl)) {
      setError('Enter a valid GitHub repository URL (or owner/repo).')
      return
    }

    const token = getAuthToken()
    if (!token) {
      router.replace('/login')
      return
    }

    setError('')
    setIsLoading(true)
    setLoadingStepIndex(0)
    setResult(null)

    let loadingTimer: ReturnType<typeof setInterval> | null = null
    if (loadingSteps.length > 1) {
      loadingTimer = setInterval(() => {
        setLoadingStepIndex((prev) => Math.min(prev + 1, loadingSteps.length - 1))
      }, 1200)
    }

    try {
      const response = await fetch(`${apiBase}${endpointForMode(config.mode)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ url: normalizedRepoUrl }),
      })

      const payload = (await response.json().catch(() => ({}))) as GenericResponse

      if (!response.ok) {
        if (response.status === 401) {
          clearAuthSession()
          router.replace('/login')
          return
        }

        setError(String(payload.message || 'Unable to run analysis.'))
        return
      }

      setResult(buildResult(config.mode, payload))
    } catch {
      setError('Unable to reach backend service. Ensure server is running.')
    } finally {
      if (loadingTimer) {
        clearInterval(loadingTimer)
      }
      setIsLoading(false)
      setLoadingStepIndex(0)
    }
  }

  return (
    <div className={isDark ? 'min-h-screen overflow-x-hidden bg-linear-to-br from-blue-950 via-slate-950 to-black text-white' : 'min-h-screen overflow-x-hidden bg-white'}>
      <Header />

      <main className={isDark ? 'overflow-x-hidden py-16' : 'overflow-x-hidden bg-linear-to-b from-white to-gray-50 py-16'}>
        <section className="container mx-auto px-4">
          <div className="mx-auto max-w-6xl space-y-8">
            <div className="text-center">
              <div className="mb-6 inline-flex items-center justify-center">
                <div className={isDark ? 'h-px w-20 bg-white/20' : 'h-px w-20 bg-gray-300'}></div>
                <h1 className={isDark ? 'px-6 text-2xl font-semibold uppercase tracking-wider text-blue-200' : 'px-6 text-2xl font-semibold uppercase tracking-wider text-gray-900'}>
                  {config.sectionLabel}
                </h1>
                <div className={isDark ? 'h-px w-20 bg-white/20' : 'h-px w-20 bg-gray-300'}></div>
              </div>
              <h2 className={isDark ? 'mb-4 text-3xl font-bold text-white md:text-4xl' : 'mb-4 text-3xl font-bold text-gray-900 md:text-4xl'}>{config.title}</h2>
              <p className={isDark ? 'mx-auto max-w-3xl text-lg text-blue-100' : 'mx-auto max-w-3xl text-lg text-gray-600'}>{config.subtitle}</p>
            </div>

            <div className={isDark ? 'rounded-2xl border border-white/10 bg-white/5 p-6 shadow-xl backdrop-blur-md md:p-8' : 'rounded-2xl border border-gray-100 bg-white p-6 shadow-xl md:p-8'}>
              <div className="flex flex-col gap-4 md:flex-row">
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
                  className={isDark ? 'flex-1 rounded-lg border border-white/20 bg-black/30 px-4 py-3 text-white placeholder:text-blue-200/70 focus:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500/40' : 'flex-1 rounded-lg border border-gray-300 px-4 py-3 text-gray-700 placeholder:text-gray-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600'}
                />
                <Button onClick={handleAnalyze} className="w-full md:w-auto" disabled={isLoading || !repoUrl.trim()}>
                  {config.buttonLabel}
                </Button>
              </div>
              {error ? <p className="mt-3 text-sm text-red-300">{error}</p> : null}
            </div>

            {isLoading && (
              <div className={isDark ? 'flex items-center justify-center rounded-2xl border border-white/10 bg-white/5 p-10 shadow-xl' : 'flex items-center justify-center rounded-2xl border border-gray-100 bg-white p-10 shadow-xl'}>
                <div className={isDark ? 'flex items-center gap-4 text-blue-100' : 'flex items-center gap-4 text-gray-700'}>
                  <div className="h-8 w-8 animate-spin rounded-full border-4 border-blue-200 border-t-blue-600"></div>
                  <span className="text-lg font-medium">{loadingLabel}</span>
                </div>
              </div>
            )}

            {result && (
              <motion.div
                className={resultPanelClass}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.45 }}
              >
                <div className={isDark ? 'rounded-xl border border-cyan-300/20 bg-linear-to-r from-cyan-400/10 via-blue-400/5 to-transparent px-4 py-3 text-xs uppercase tracking-wider text-cyan-100' : 'rounded-xl border border-blue-100 bg-blue-50 px-4 py-3 text-xs uppercase tracking-wider text-blue-700'}>
                  Analysis complete. All values below are from backend response.
                </div>

                <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
                  <motion.article initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }} className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-3 text-sm font-semibold uppercase tracking-wide text-blue-200' : 'mb-3 text-sm font-semibold uppercase tracking-wide text-gray-500'}>Overall Score</h3>
                    <div className="mb-2 text-4xl font-bold text-blue-600">{result.scoreText}</div>
                    <p className={isDark ? 'text-sm text-blue-100' : 'text-sm text-gray-600'}>{result.scoreCaption}</p>
                  </motion.article>

                  <motion.article initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.06 }} className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-3 text-sm font-semibold uppercase tracking-wide text-blue-200' : 'mb-3 text-sm font-semibold uppercase tracking-wide text-gray-500'}>{result.statusTitle}</h3>
                    <div className="mb-2 text-2xl font-bold text-cyan-300">{result.statusValue}</div>
                    <p className={isDark ? 'text-sm text-blue-100' : 'text-sm text-gray-600'}>{result.statusDescription}</p>
                  </motion.article>

                  <motion.article initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.12 }} className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-4 text-sm font-semibold uppercase tracking-wide text-blue-200' : 'mb-4 text-sm font-semibold uppercase tracking-wide text-gray-500'}>Repository Info</h3>
                    <div className="mb-4">
                      <p className={isDark ? 'break-all text-lg font-semibold text-white' : 'break-all text-lg font-semibold text-gray-900'}>{result.repoName}</p>
                      <p className={isDark ? 'mt-1 break-all text-sm text-blue-100' : 'mt-1 break-all text-sm text-gray-600'}>{result.repoDescription}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                      {result.repoMetrics.map((metric) => (
                        <div key={metric.label} className={isDark ? 'rounded-lg border border-white/10 bg-black/20 p-3' : 'rounded-lg border border-gray-100 bg-gray-50 p-3'}>
                          <p className={isDark ? 'text-xs uppercase tracking-wide text-blue-200' : 'text-xs uppercase tracking-wide text-gray-500'}>{metric.label}</p>
                          <p className={isDark ? 'mt-1 text-sm font-semibold text-white' : 'mt-1 text-sm font-semibold text-gray-900'}>{metric.value}</p>
                        </div>
                      ))}
                    </div>
                  </motion.article>
                </div>

                <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
                  <article className={`${resultCardClass} p-5`}>
                    <p className={isDark ? 'text-xs uppercase tracking-wide text-blue-200' : 'text-xs uppercase tracking-wide text-gray-500'}>License Status</p>
                    <p className={isDark ? `mt-2 text-2xl font-bold ${hasLicense ? 'text-emerald-300' : 'text-red-300'}` : `mt-2 text-2xl font-bold ${hasLicense ? 'text-emerald-600' : 'text-red-600'}`}>
                      {hasLicense ? 'VALID LICENSE' : 'MISSING LICENSE'}
                    </p>
                    <p className={isDark ? 'mt-2 text-sm text-blue-100' : 'mt-2 text-sm text-gray-600'}>
                      {`Detected: ${detectedLicense}`}
                      {result?.licenseDetection?.confidence ? ` (${result.licenseDetection.confidence} confidence)` : ''}
                      {result?.licenseDetection?.source ? ` via ${result.licenseDetection.source}` : ''}
                    </p>
                  </article>

                  <article className={`${resultCardClass} p-5`}>
                    <p className={isDark ? 'text-xs uppercase tracking-wide text-blue-200' : 'text-xs uppercase tracking-wide text-gray-500'}>Average Metric Score</p>
                    <p className="mt-2 text-2xl font-bold text-blue-400">{averageReadiness}%</p>
                    <p className={isDark ? 'mt-2 text-sm text-blue-100' : 'mt-2 text-sm text-gray-600'}>
                      Mean score across progress metrics derived from backend data.
                    </p>
                  </article>

                  <article className={`${resultCardClass} p-5`}>
                    <p className={isDark ? 'text-xs uppercase tracking-wide text-blue-200' : 'text-xs uppercase tracking-wide text-gray-500'}>Strongest Signal</p>
                    <p className="mt-2 text-2xl font-bold text-blue-400">{strongestSignal ? strongestSignal.label : 'N/A'}</p>
                    <p className={isDark ? 'mt-2 text-sm text-blue-100' : 'mt-2 text-sm text-gray-600'}>
                      {strongestSignal ? `${Math.round(strongestSignal.value)}% contribution` : 'No distribution metrics available.'}
                    </p>
                  </article>
                </div>

                <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-5 text-xl font-semibold text-white' : 'mb-5 text-xl font-semibold text-gray-900'}>Distribution Metrics</h3>
                    <div className="space-y-4">
                      {normalizedDistributionMetrics.map((item) => (
                        <div key={item.label}>
                          <div className="mb-2 flex items-center justify-between text-sm">
                            <span className={isDark ? 'font-medium text-blue-100' : 'font-medium text-gray-700'}>{item.label}</span>
                            <span className={isDark ? 'text-blue-200' : 'text-gray-600'}>{Math.round(item.value)}%</span>
                          </div>
                          <div className={isDark ? 'h-2 overflow-hidden rounded-full bg-white/10' : 'h-2 overflow-hidden rounded-full bg-gray-200'}>
                            <div className={`h-full rounded-full ${item.barClassName ?? 'bg-blue-600'}`} style={{ width: `${item.value}%` }}></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-5 text-xl font-semibold text-white' : 'mb-5 text-xl font-semibold text-gray-900'}>Progress Metrics</h3>
                    <div className="space-y-4">
                      {normalizedProgressMetrics.map((metric) => (
                        <div key={metric.label}>
                          <div className="mb-2 flex items-center justify-between text-sm">
                            <span className={isDark ? 'font-medium text-blue-100' : 'font-medium text-gray-700'}>{metric.label}</span>
                            <span className={isDark ? 'text-blue-200' : 'text-gray-600'}>{metric.value}</span>
                          </div>
                          <div className={isDark ? 'h-2 overflow-hidden rounded-full bg-white/10' : 'h-2 overflow-hidden rounded-full bg-gray-200'}>
                            <div className="h-full rounded-full bg-blue-600" style={{ width: `${metric.progress}%` }}></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>
                </div>

                <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-5 text-xl font-semibold text-white' : 'mb-5 text-xl font-semibold text-gray-900'}>Bar Chart: Repository Composition</h3>
                    <div className={isDark ? 'rounded-xl border border-white/10 bg-black/20 p-4' : 'rounded-xl border border-gray-100 bg-gray-50 p-4'}>
                      <div className="mx-auto flex h-52 max-w-3xl items-end justify-center gap-3">
                        {normalizedDistributionMetrics.map((item) => (
                          <div key={item.label} className="flex h-full flex-1 flex-col items-center justify-end gap-2">
                            <p className={isDark ? 'text-xs font-semibold text-blue-200' : 'text-xs font-semibold text-gray-700'}>{Math.round(item.value)}%</p>
                            <motion.div
                              title={`${item.label}: ${Math.round(item.value)}%`}
                              initial={{ height: 0, opacity: 0.6 }}
                              animate={{ height: Math.max((item.value / 100) * 150, 12), opacity: 1 }}
                              transition={{ duration: 0.5 }}
                              className={isDark ? 'w-full rounded-t-md border border-blue-300/30 bg-blue-500/80' : 'w-full rounded-t-md bg-blue-500'}
                            />
                            <p className={isDark ? 'text-center text-[11px] text-blue-100' : 'text-center text-[11px] text-gray-700'}>{item.label}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </article>

                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-5 text-xl font-semibold text-white' : 'mb-5 text-xl font-semibold text-gray-900'}>Trend Chart: Readiness Metrics</h3>
                    <div className={isDark ? 'rounded-xl border border-white/10 bg-black/20 p-4' : 'rounded-xl border border-gray-100 bg-gray-50 p-4'}>
                      <svg viewBox="0 0 100 100" className="h-44 w-full">
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
                              <text x={x} y={Math.max(y - 4, 8)} textAnchor="middle" fontSize="4" fill={isDark ? '#bfdbfe' : '#1d4ed8'} fontWeight="700">
                                {Math.round(metric.progress)}%
                              </text>
                            </g>
                          )
                        })}
                      </svg>
                      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                        {normalizedProgressMetrics.map((metric) => (
                          <div key={`label-${metric.label}`} className={isDark ? 'rounded-lg border border-white/10 bg-black/20 px-2 py-1 text-[11px] text-blue-100' : 'rounded-lg border border-gray-200 bg-white px-2 py-1 text-[11px] text-gray-700'}>
                            <span className="font-semibold">{metric.label}:</span> {Math.round(metric.progress)}%
                          </div>
                        ))}
                      </div>
                    </div>
                  </article>
                </div>

                {result.malwareExplanation && (
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-3 text-xl font-semibold text-white' : 'mb-3 text-xl font-semibold text-gray-900'}>Why This Repo Is Risky</h3>
                    <p className={isDark ? 'mb-4 leading-relaxed text-blue-100' : 'mb-4 leading-relaxed text-gray-700'}>
                      {result.malwareExplanation.summary || result.malwareExplanation.verdictReason || 'No risk narrative returned.'}
                    </p>
                    {Array.isArray(result.malwareExplanation.keyFindings) && result.malwareExplanation.keyFindings.length > 0 && (
                      <ul className="space-y-2">
                        {result.malwareExplanation.keyFindings.slice(0, 6).map((finding) => (
                          <li key={finding} className={isDark ? 'text-sm text-blue-100' : 'text-sm text-gray-700'}>
                            • {finding}
                          </li>
                        ))}
                      </ul>
                    )}
                    {Array.isArray(result.malwareExplanation.combinations) && result.malwareExplanation.combinations.length > 0 && (
                      <p className={isDark ? 'mt-4 text-sm font-medium text-cyan-200' : 'mt-4 text-sm font-medium text-blue-700'}>
                        High-risk combinations: {result.malwareExplanation.combinations.join(', ')}
                      </p>
                    )}
                  </article>
                )}

                {result.malwareExplanation && Array.isArray(result.malwareExplanation.technicalDetails) && result.malwareExplanation.technicalDetails.length > 0 && (
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-4 text-xl font-semibold text-white' : 'mb-4 text-xl font-semibold text-gray-900'}>Technical Breakdown</h3>
                    <div className="space-y-3">
                      {result.malwareExplanation.technicalDetails.slice(0, 6).map((detail) => (
                        <details key={`${detail.category}-${detail.riskContribution}`} className={isDark ? 'rounded-lg border border-white/10 bg-black/20 p-3' : 'rounded-lg border border-gray-200 bg-gray-50 p-3'}>
                          <summary className={isDark ? 'cursor-pointer font-medium text-blue-100' : 'cursor-pointer font-medium text-gray-800'}>
                            {toTitle(detail.category)} - {detail.riskContribution}% contribution
                          </summary>
                          <p className={isDark ? 'mt-2 text-xs text-blue-200' : 'mt-2 text-xs text-gray-600'}>
                            Matched patterns: {detail.matchedPatterns.join(', ') || 'N/A'}
                          </p>
                        </details>
                      ))}
                    </div>
                  </article>
                )}

                {result.aiInsights && (
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-4 text-xl font-semibold text-white' : 'mb-4 text-xl font-semibold text-gray-900'}>AI Insights</h3>
                    <p className={isDark ? 'mb-3 text-blue-100' : 'mb-3 text-gray-700'}>{result.aiInsights.summary || 'No AI summary available.'}</p>
                    {Array.isArray(result.aiInsights.risks) && result.aiInsights.risks.length > 0 && (
                      <div className="mb-3">
                        <p className={isDark ? 'mb-1 text-xs uppercase tracking-wide text-blue-200' : 'mb-1 text-xs uppercase tracking-wide text-gray-500'}>Risks</p>
                        <ul className="space-y-1">
                          {result.aiInsights.risks.slice(0, 6).map((risk) => (
                            <li key={risk} className={isDark ? 'text-sm text-blue-100' : 'text-sm text-gray-700'}>• {risk}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {aiInsightRecommendations.length > 0 && (
                      <div>
                        <p className={isDark ? 'mb-1 text-xs uppercase tracking-wide text-blue-200' : 'mb-1 text-xs uppercase tracking-wide text-gray-500'}>Recommendations</p>
                        <ul className="space-y-2">
                          {aiInsightRecommendations.slice(0, 6).map((rec) => (
                            <li key={`${rec.priority}-${rec.action}`} className={isDark ? 'text-sm text-blue-100' : 'text-sm text-gray-700'}>
                              <span className={isDark ? 'mr-2 rounded bg-blue-500/20 px-2 py-0.5 text-xs font-semibold text-blue-200' : 'mr-2 rounded bg-blue-100 px-2 py-0.5 text-xs font-semibold text-blue-700'}>{rec.priority}</span>
                              {rec.action}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </article>
                )}

                {result.trustReport && (
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-3 text-xl font-semibold text-white' : 'mb-3 text-xl font-semibold text-gray-900'}>Trust Explanation</h3>
                    <p className={isDark ? 'mb-2 text-blue-100' : 'mb-2 text-gray-700'}>
                      Trust Score: <span className="font-semibold">{Math.round(safeNumber(result.trustReport.trustScore, 0))}</span> - {result.trustReport.verdict || 'Unknown'}
                    </p>
                    <p className={isDark ? 'mb-4 text-sm text-blue-200' : 'mb-4 text-sm text-gray-600'}>{result.trustReport.explanation || 'No trust explanation provided.'}</p>
                    <div className="space-y-3">
                      {trustMetrics.map((metric) => (
                        <div key={`trust-${metric.label}`}>
                          <div className="mb-1 flex items-center justify-between text-xs">
                            <span className={isDark ? 'text-blue-100' : 'text-gray-700'}>{metric.label}</span>
                            <span className={isDark ? 'text-blue-200' : 'text-gray-600'}>{metric.value}</span>
                          </div>
                          <div className={isDark ? 'h-2 overflow-hidden rounded-full bg-white/10' : 'h-2 overflow-hidden rounded-full bg-gray-200'}>
                            <div className="h-full rounded-full bg-cyan-500" style={{ width: `${metric.progress}%` }}></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>
                )}

                <article className={`${resultCardClass} p-6`}>
                  <h3 className={isDark ? 'mb-3 text-xl font-semibold text-white' : 'mb-3 text-xl font-semibold text-gray-900'}>Summary</h3>
                  <p className={isDark ? 'leading-relaxed text-blue-100' : 'leading-relaxed text-gray-700'}>{result.summaryText}</p>
                </article>

                {result.roadmapItems.length > 0 && (
                  <article className={`${resultCardClass} p-6`}>
                    <h3 className={isDark ? 'mb-4 text-xl font-semibold text-white' : 'mb-4 text-xl font-semibold text-gray-900'}>Roadmap</h3>
                    <ul className="space-y-3">
                      {result.roadmapItems.map((item) => (
                        <li key={item} className={isDark ? 'flex items-start gap-3 text-blue-100' : 'flex items-start gap-3 text-gray-700'}>
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-100 text-sm font-semibold text-blue-600">✓</span>
                          <span className="pt-0.5">{item}</span>
                        </li>
                      ))}
                    </ul>
                  </article>
                )}

                {config.mode !== 'human' && (
                  <article className="rounded-2xl border border-gray-800 bg-gray-900 p-6 shadow-xl">
                    <h3 className="mb-4 text-lg font-semibold text-white">Raw Backend Output</h3>
                    <pre className="overflow-x-auto whitespace-pre-wrap text-xs text-gray-100 md:text-sm">{prettyRawOutput}</pre>
                  </article>
                )}
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
