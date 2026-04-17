"use client"

import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { motion } from 'framer-motion'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import {
  ArrowRight,
  BookOpen,
  CheckCircle2,
  ExternalLink,
  FolderTree,
  GitBranch,
  Info,
  Loader2,
  Shield,
  Sparkles,
  Target,
  TrendingUp,
} from 'lucide-react'
import Header from '@/components/layout/Header'
import Footer from '@/components/layout/Footer'
import { getLicenseInfo } from '@/lib/licenseDetails'
import { clearAuthSession, getAuthToken } from '@/lib/authSession'

type ScoreBreakdownItem = {
  key: string
  label: string
  score: number
  max: number
}

type RepoAnalysisResponse = {
  input?: {
    owner?: string
    repo?: string
    url?: string
  }
  repo?: {
    fullName?: string
    htmlUrl?: string
    description?: string | null
    defaultBranch?: string
    isFork?: boolean
    visibility?: string
    stars?: number
    forks?: number
    watchers?: number
    openIssues?: number
    license?: string | null
    topics?: string[]
    createdAt?: string
    updatedAt?: string
    pushedAt?: string
    sizeKb?: number
  }
  snapshot?: {
    files?: {
      fileCount?: number
      directoryCount?: number
      truncated?: boolean
      topLevelCounts?: Record<string, number>
    }
    languagesTop?: Array<{ name: string; bytes?: number; percent: number }>
    readme?: {
      present?: boolean
      wordCount?: number
      hasInstall?: boolean
      hasUsage?: boolean
      hasScreenshots?: boolean
      hasBadges?: boolean
    }
    tooling?: {
      hasEslint?: boolean
      hasPrettier?: boolean
      hasEditorConfig?: boolean
      hasGitHubActions?: boolean
      hasDependabot?: boolean
      hasTestsDir?: boolean
      hasDocsDir?: boolean
      hasSrcDir?: boolean
      hasLockfile?: boolean
      hasDocker?: boolean
      hasEnvExample?: boolean
      hasContributingFile?: boolean
      hasCodeOfConduct?: boolean
      hasChangelog?: boolean
      hasSecurityPolicy?: boolean
      hasIssueTemplates?: boolean
      hasPullRequestTemplate?: boolean
      hasGitIgnore?: boolean
      hasDeployConfig?: boolean
    }
    git?: {
      commitsLast90Days?: number
      commitsLast90DaysCapped?: boolean
      activeCommitDaysLast90Days?: number
      conventionalCommitRate?: number
      branches?: number
      pullRequests?: number
      contributors?: number
      releases?: number
    }
  }
  score?: {
    total?: number
    value?: number
    level?: string
    band?: string
    badge?: string
    breakdown?: ScoreBreakdownItem[]
  }
  summary?: string
  roadmap?: string[]
}

type ScoreRingProps = {
  score: number
}

const PIE_COLORS = ['#58a6ff', '#79c0ff', '#1f6feb', '#3fb950', '#f2cc60', '#f0883e']
const CARD_CLASS = 'rounded-2xl border border-[#30363d] bg-surface-1 p-5'

function clamp(value: number, min = 0, max = 100) {
  return Math.min(Math.max(value, min), max)
}

function formatPercent(value: number) {
  return `${Math.round(value * 100)}%`
}

function formatDate(iso?: string) {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  })
}

function getSummaryHighlights(summary?: string) {
  if (!summary) return []
  return summary
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, 3)
}

function isDetectedLicense(license: string | null | undefined) {
  if (typeof license !== 'string') return false
  const value = license.trim()
  if (!value) return false
  return value.toUpperCase() !== 'NOASSERTION'
}

function ScoreRing({ score }: ScoreRingProps) {
  const radius = 62
  const circumference = 2 * Math.PI * radius
  const clamped = clamp(score)
  const strokeOffset = circumference - (clamped / 100) * circumference
  const [displayedScore, setDisplayedScore] = useState(0)
  const frameRef = useRef<number | null>(null)

  useEffect(() => {
    const duration = 1200
    const start = performance.now()

    const tick = (now: number) => {
      const progress = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplayedScore(Math.round(clamped * eased))

      if (progress < 1) frameRef.current = requestAnimationFrame(tick)
    }

    frameRef.current = requestAnimationFrame(tick)

    return () => {
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current)
    }
  }, [clamped])

  return (
    <div className="relative h-40 w-40">
      <svg className="h-40 w-40 -rotate-90" viewBox="0 0 160 160" role="img" aria-label={`Score ${clamped} out of 100`}>
        <circle cx="80" cy="80" r={radius} fill="none" stroke="#1f2a3d" strokeWidth="14" />
        <motion.circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke="url(#scoreGradient)"
          strokeWidth="14"
          strokeLinecap="round"
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: strokeOffset }}
          transition={{ duration: 1.2, ease: 'easeOut' }}
          strokeDasharray={circumference}
        />
        <defs>
          <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#79c0ff" />
            <stop offset="60%" stopColor="#58a6ff" />
            <stop offset="100%" stopColor="#1f6feb" />
          </linearGradient>
        </defs>
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-3xl font-bold text-white tabular-nums">{displayedScore}</div>
        <div className="text-xs text-[#8b949e]">out of 100</div>
      </div>
    </div>
  )
}

export default function AnalyzePage() {
  const router = useRouter()
  const [repoUrl, setRepoUrl] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<RepoAnalysisResponse | null>(null)

  const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:5000'

  const token = useSyncExternalStore(
    (onStoreChange) => {
      if (typeof window === 'undefined') return () => {}

      const handleChange = () => onStoreChange()
      window.addEventListener('storage', handleChange)
      window.addEventListener('focus', handleChange)

      return () => {
        window.removeEventListener('storage', handleChange)
        window.removeEventListener('focus', handleChange)
      }
    },
    () => {
      if (typeof window === 'undefined') return null
      return localStorage.getItem('gitguard_token')
    },
    () => null,
  )

  useEffect(() => {
    if (!token) {
      router.replace('/login')
    }
  }, [router, token])

  const totalScore = useMemo(() => clamp(result?.score?.total ?? result?.score?.value ?? 0), [result])

  const breakdownChart = useMemo(
    () =>
      (result?.score?.breakdown ?? []).map((item) => ({
        name: item.label.length > 18 ? `${item.label.slice(0, 18)}...` : item.label,
        score: Number(((item.score / Math.max(item.max, 1)) * 100).toFixed(1)),
      })),
    [result],
  )

  const languageChart = useMemo(() => {
    return (result?.snapshot?.languagesTop ?? []).slice(0, 6).map((lang, idx) => ({
      ...lang,
      color: PIE_COLORS[idx % PIE_COLORS.length],
    }))
  }, [result])

  const activityBars = useMemo(() => {
    const git = result?.snapshot?.git
    if (!git) return []

    return [
      { label: 'Commit volume', value: Math.min(100, git.commitsLast90Days ?? 0) },
      { label: 'Active days', value: Math.min(100, Math.round(((git.activeCommitDaysLast90Days ?? 0) / 90) * 100)) },
      { label: 'PR rhythm', value: Math.min(100, (git.pullRequests ?? 0) * 8) },
    ]
  }, [result])

  const signalMix = useMemo(() => {
    const git = result?.snapshot?.git
    const readme = result?.snapshot?.readme
    const tooling = result?.snapshot?.tooling

    const activity = Math.min(100, (git?.commitsLast90Days ?? 0) + (git?.pullRequests ?? 0) * 6)
    const documentation = Math.min(
      100,
      (readme?.wordCount ?? 0) / 12 +
        (readme?.hasInstall ? 12 : 0) +
        (readme?.hasUsage ? 12 : 0) +
        (readme?.hasScreenshots ? 8 : 0) +
        (readme?.hasBadges ? 8 : 0),
    )
    const security = Math.min(
      100,
      (tooling?.hasSecurityPolicy ? 35 : 0) +
        (tooling?.hasDependabot ? 25 : 0) +
        (tooling?.hasGitHubActions ? 20 : 0) +
        (tooling?.hasIssueTemplates ? 10 : 0) +
        (tooling?.hasPullRequestTemplate ? 10 : 0),
    )
    const quality = Math.min(
      100,
      (tooling?.hasEslint ? 25 : 0) +
        (tooling?.hasPrettier ? 20 : 0) +
        (tooling?.hasTestsDir ? 25 : 0) +
        (tooling?.hasEditorConfig ? 10 : 0) +
        (tooling?.hasContributingFile ? 20 : 0),
    )

    return [
      { label: 'Activity', value: activity, color: '#58a6ff' },
      { label: 'Documentation', value: documentation, color: '#79c0ff' },
      { label: 'Security', value: security, color: '#3fb950' },
      { label: 'Quality', value: quality, color: '#f2cc60' },
    ]
  }, [result])

  const momentumBars = useMemo(() => {
    const git = result?.snapshot?.git
    const contributors = git?.contributors ?? 0
    const branches = git?.branches ?? 0
    const releases = git?.releases ?? 0
    const commits = git?.commitsLast90Days ?? 0

    return [
      { label: 'Contributors', value: Math.min(100, contributors * 8), raw: contributors },
      { label: 'Branches', value: Math.min(100, branches * 6), raw: branches },
      { label: 'Releases', value: Math.min(100, releases * 20), raw: releases },
      { label: 'Commits 90d', value: Math.min(100, commits), raw: commits },
    ]
  }, [result])

  const signalMixGradient = useMemo(() => {
    const total = signalMix.reduce((acc, item) => acc + item.value, 0)
    if (total <= 0) return '#1f2a3d'

    let cursor = 0
    const parts = signalMix.map((item) => {
      const width = (item.value / total) * 100
      const start = cursor
      const end = cursor + width
      cursor = end
      return `${item.color} ${start}% ${end}%`
    })

    if (cursor < 100) parts.push(`#1f2a3d ${cursor}% 100%`)
    return `conic-gradient(${parts.join(', ')})`
  }, [signalMix])

  const toolingSignals = useMemo(() => {
    const tooling = result?.snapshot?.tooling
    if (!tooling) return [] as Array<{ label: string; active: boolean }>

    return [
      { label: 'ESLint', active: Boolean(tooling.hasEslint) },
      { label: 'Prettier', active: Boolean(tooling.hasPrettier) },
      { label: 'GitHub Actions', active: Boolean(tooling.hasGitHubActions) },
      { label: 'Dependabot', active: Boolean(tooling.hasDependabot) },
      { label: 'Security Policy', active: Boolean(tooling.hasSecurityPolicy) },
      { label: 'Issue Templates', active: Boolean(tooling.hasIssueTemplates) },
      { label: 'PR Template', active: Boolean(tooling.hasPullRequestTemplate) },
      { label: 'Contributing File', active: Boolean(tooling.hasContributingFile) },
    ]
  }, [result])

  const topLevelList = useMemo(() => {
    const entries = Object.entries(result?.snapshot?.files?.topLevelCounts ?? {})
    return entries.sort((a, b) => b[1] - a[1]).slice(0, 6)
  }, [result])

  const licenseInfo = useMemo(() => getLicenseInfo(result?.repo?.license ?? null), [result?.repo?.license])

  const handleAnalyze = async (event: React.FormEvent) => {
    event.preventDefault()
    if (submitting) return

    if (!repoUrl.trim()) {
      setError('Please enter a GitHub repository URL.')
      return
    }

    setError(null)
    setSubmitting(true)

    try {
      const currentToken = getAuthToken()
      if (!currentToken) {
        router.replace('/login')
        return
      }

      const response = await fetch(`${apiBase}/api/repo/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${currentToken}`,
        },
        body: JSON.stringify({ url: repoUrl.trim() }),
      })

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        if (response.status === 401) {
          clearAuthSession()
          router.replace('/login')
          return
        }

        setResult(null)
        setError(typeof data?.message === 'string' ? data.message : 'Unable to analyze repository.')
        return
      }

      setResult(data as RepoAnalysisResponse)
    } catch {
      setResult(null)
      setError('Unable to analyze repository. Verify backend is running.')
    } finally {
      setSubmitting(false)
    }
  }

  if (!token) return <div className="min-h-screen bg-background" />

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <main>
        <section className="relative overflow-hidden bg-background pt-16 pb-20">
          <div className="pointer-events-none absolute inset-0">
            <div
              className="h-full w-full opacity-[0.08]"
              style={{
                backgroundImage:
                  'linear-gradient(to right, #58a6ff 1px, transparent 1px), linear-gradient(to bottom, #58a6ff 1px, transparent 1px)',
                backgroundSize: '74px 74px',
              }}
            />
            <div className="absolute left-1/4 top-10 h-52 w-52 rounded-full bg-[#1f6feb]/20 blur-3xl" />
            <div className="absolute right-1/4 bottom-0 h-52 w-52 rounded-full bg-[#58a6ff]/20 blur-3xl" />
          </div>

          <div className="container relative z-10 mx-auto px-4 sm:px-6 lg:px-10">
            <div className="mx-auto max-w-6xl">
              <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45 }}>
                <div className="rs-glow inline-flex items-center gap-2 rounded-full border border-[#30363d] bg-surface-1 px-3 py-1 text-sm">
                  <Sparkles className="h-4 w-4 text-[#58a6ff]" />
                  <span className="text-[#c9d1d9]">Repository Quality Lab</span>
                </div>

                <h1 className="rs-text-glow mt-4 text-3xl font-bold leading-tight text-white sm:text-4xl lg:text-5xl">
                  Analyze repository health
                </h1>
                <p className="mt-3 max-w-2xl text-base leading-relaxed text-[#8b949e] sm:text-lg">
                  Get graph-first insights, tooling confidence, and a practical roadmap to evaluate repos like a pro.
                </p>

                <form onSubmit={handleAnalyze} className="mt-8 rounded-2xl border border-[#30363d] bg-surface-1/90 p-4 sm:p-6">
                  <label htmlFor="repo-url" className="text-sm text-[#c9d1d9]">
                    GitHub Repository URL
                  </label>

                  <div className="mt-2 flex flex-col gap-3 sm:flex-row">
                    <input
                      id="repo-url"
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                      placeholder="https://github.com/owner/repo"
                      className="w-full rounded-xl border border-[#30363d] bg-background px-4 py-3 text-white placeholder:text-[#6e7681] outline-none focus:border-[#58a6ff] focus:ring-1 focus:ring-[#58a6ff]"
                      disabled={submitting}
                      required
                    />

                    <button
                      type="submit"
                      disabled={submitting}
                      className="inline-flex min-w-36 items-center justify-center rounded-xl border-0 bg-[#1f6feb] px-5 py-3 font-semibold text-white shadow-lg shadow-[#1f6feb]/20 transition hover:bg-[#388bfd] disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {submitting ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Analyzing
                        </>
                      ) : (
                        <>
                          Analyze
                          <ArrowRight className="ml-2 h-4 w-4" />
                        </>
                      )}
                    </button>
                  </div>

                  {error ? <p className="mt-3 text-xs text-red-400">{error}</p> : null}
                </form>
              </motion.div>

              {result ? (
                <motion.div
                  className="mt-10 space-y-6"
                  initial={{ opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5 }}
                >
                  <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
                    <div className={CARD_CLASS}>
                      <div className="mb-4 flex items-center justify-between">
                        <div className="text-xs uppercase tracking-[0.18em] text-[#8b949e]">Score</div>
                        <span className="rounded-full border border-[#2a3344] bg-background/40 px-2 py-1 text-[11px] text-[#c9d1d9]">
                          {result.score?.level ?? result.score?.band ?? 'Unknown'}
                        </span>
                      </div>

                      <div className="flex items-center justify-center">
                        <ScoreRing score={totalScore} />
                      </div>

                      <div className="mt-4 text-center text-sm text-[#8b949e]">Badge: {result.score?.badge ?? 'N/A'}</div>
                    </div>

                    <div className={`${CARD_CLASS} lg:col-span-2`}>
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <div className="text-xs uppercase tracking-[0.18em] text-[#8b949e]">Repository</div>
                          <div className="mt-1 wrap-break-word text-lg font-semibold text-white">{result.repo?.fullName ?? 'N/A'}</div>
                          <p className="mt-1 text-sm leading-relaxed text-[#8b949e]">{result.repo?.description || 'No description provided.'}</p>
                        </div>

                        {result.repo?.htmlUrl ? (
                          <Link
                            href={result.repo.htmlUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 whitespace-nowrap text-sm text-[#58a6ff] hover:underline"
                          >
                            View on GitHub
                            <ExternalLink className="h-4 w-4" />
                          </Link>
                        ) : null}
                      </div>

                      <div className="mt-4 rounded-lg border border-[#30363d] bg-surface-2 p-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="text-sm font-medium text-white">License status</div>
                            <div className="text-xs text-[#8b949e]">{isDetectedLicense(result.repo?.license) ? `Detected: ${result.repo?.license}` : 'No license detected'}</div>
                          </div>
                          {isDetectedLicense(result.repo?.license) ? (
                            <span className="inline-flex items-center gap-1 rounded-full border border-[#2e7d47] bg-[#1f6f3a]/20 px-2 py-1 text-xs text-[#8ad8ab]"><CheckCircle2 className="h-3.5 w-3.5" />Healthy</span>
                          ) : (
                            <span className="rounded-full border border-red-700/60 bg-red-950/30 px-2 py-1 text-xs text-red-300">Warning</span>
                          )}
                        </div>

                        {licenseInfo && (
                          <div className="mt-4 border-t border-[#2a3344] pt-3">
                            <div className="mb-2 text-sm font-medium text-[#79c0ff]">{licenseInfo.title}</div>
                            <ul className="space-y-2 text-xs text-[#c9d1d9]">
                              {licenseInfo.points.map((point) => (
                                <li key={point} className="flex items-start gap-2">
                                  <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 text-[#58a6ff]" />
                                  <span>{point}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>

                      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
                        <div className="rounded-lg border border-[#30363d] bg-surface-2 p-3"><div className="text-[10px] text-[#8b949e]">Stars</div><div className="font-semibold text-white">{result.repo?.stars ?? 0}</div></div>
                        <div className="rounded-lg border border-[#30363d] bg-surface-2 p-3"><div className="text-[10px] text-[#8b949e]">Watchers</div><div className="font-semibold text-white">{result.repo?.watchers ?? 0}</div></div>
                        <div className="rounded-lg border border-[#30363d] bg-surface-2 p-3"><div className="text-[10px] text-[#8b949e]">Forks</div><div className="font-semibold text-white">{result.repo?.forks ?? 0}</div></div>
                        <div className="rounded-lg border border-[#30363d] bg-surface-2 p-3"><div className="text-[10px] text-[#8b949e]">Open Issues</div><div className="font-semibold text-white">{result.repo?.openIssues ?? 0}</div></div>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                    <div className={CARD_CLASS}>
                      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><Target className="h-4 w-4 text-[#58a6ff]" />Signal Mix</div>
                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                        <div className="flex items-center justify-center rounded-xl border border-[#2a3344] bg-surface-2 p-4">
                          <div className="grid h-36 w-36 place-items-center rounded-full" style={{ background: signalMixGradient }}>
                            <div className="grid h-22 w-22 place-items-center rounded-full bg-background text-center">
                              <div className="text-sm font-semibold text-white">Signals</div>
                              <div className="text-[10px] text-[#8b949e]">quality mix</div>
                            </div>
                          </div>
                        </div>

                        <div className="space-y-2 rounded-xl border border-[#2a3344] bg-surface-2 p-3">
                          {signalMix.map((item) => (
                            <div key={item.label}>
                              <div className="mb-1 flex items-center justify-between text-xs text-[#8b949e]"><span>{item.label}</span><span>{Math.round(item.value)}</span></div>
                              <div className="h-2 overflow-hidden rounded-full bg-[#1f2a3d]"><motion.div className="h-full rounded-full" style={{ backgroundColor: item.color }} initial={{ width: 0 }} animate={{ width: `${item.value}%` }} transition={{ duration: 0.75, ease: 'easeOut' }} /></div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className={CARD_CLASS}>
                      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><TrendingUp className="h-4 w-4 text-[#58a6ff]" />Repository Momentum</div>
                      <div className="space-y-3">
                        {momentumBars.map((item) => (
                          <div key={item.label}>
                            <div className="mb-1 flex items-center justify-between text-xs text-[#8b949e]"><span>{item.label}</span><span>{item.raw}</span></div>
                            <div className="h-2.5 overflow-hidden rounded-full bg-[#1f2a3d]"><motion.div className="h-full rounded-full bg-linear-to-r from-[#58a6ff] via-[#79c0ff] to-[#1f6feb]" initial={{ width: 0 }} animate={{ width: `${item.value}%` }} transition={{ duration: 0.85, ease: 'easeOut' }} /></div>
                          </div>
                        ))}
                      </div>
                      <div className="mt-4 rounded-lg border border-[#2a3344] bg-surface-2 p-3 text-xs text-[#8b949e]">
                        Momentum combines collaborators, branch activity, release cadence, and recent commit volume.
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                    <div className={CARD_CLASS}>
                      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><Target className="h-4 w-4 text-[#58a6ff]" />Score Breakdown</div>
                      <div className="rounded-xl border border-[#2a3344] bg-surface-2 p-4">
                        <div className="flex h-52 items-end gap-3 border-b border-[#2a3344] pb-3">
                          {(breakdownChart.length > 0 ? breakdownChart : [{ name: 'Overall score', score: totalScore }]).map((item, index) => (
                            <div key={item.name} className="flex flex-1 flex-col items-center justify-end gap-2">
                              <span className="text-[11px] font-semibold text-[#c9d1d9]">{item.score}%</span>
                              <div className="relative flex h-40 w-full max-w-14 items-end overflow-hidden rounded-t-md bg-[#1f2a3d]">
                                <motion.div
                                  className="w-full rounded-t-md"
                                  style={{ backgroundColor: PIE_COLORS[index % PIE_COLORS.length] }}
                                  initial={{ height: 0 }}
                                  animate={{ height: `${item.score}%` }}
                                  transition={{ duration: 0.85, ease: 'easeOut' }}
                                />
                              </div>
                              <span className="line-clamp-2 text-center text-[11px] text-[#8b949e]">{item.name}</span>
                            </div>
                          ))}
                        </div>
                        <div className="mt-2 flex items-center justify-between text-[10px] text-[#6e7681]">
                          <span>0%</span>
                          <span>50%</span>
                          <span>100%</span>
                        </div>
                      </div>
                    </div>

                    <div className={CARD_CLASS}>
                      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><TrendingUp className="h-4 w-4 text-[#58a6ff]" />Languages and Activity</div>
                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                        <div className="rounded-xl border border-[#2a3344] bg-surface-2 p-3">
                          <div className="mb-2 text-xs text-[#8b949e]">Top Languages</div>
                          <div className="space-y-2">
                            {languageChart.length > 0 ? languageChart.map((lang) => (
                              <div key={lang.name}>
                                <div className="mb-1 flex items-center justify-between text-xs text-[#8b949e]"><span>{lang.name}</span><span>{lang.percent.toFixed(1)}%</span></div>
                                <div className="h-2 overflow-hidden rounded-full bg-[#1f2a3d]"><motion.div className="h-full rounded-full" style={{ backgroundColor: lang.color }} initial={{ width: 0 }} animate={{ width: `${clamp(lang.percent)}%` }} transition={{ duration: 0.7, ease: 'easeOut' }} /></div>
                              </div>
                            )) : <div className="text-xs text-[#8b949e]">No language data</div>}
                          </div>
                        </div>

                        <div className="rounded-xl border border-[#2a3344] bg-surface-2 p-3">
                          <div className="space-y-3">
                            {activityBars.map((item) => (
                              <div key={item.label}>
                                <div className="mb-1 flex items-center justify-between text-xs text-[#8b949e]"><span>{item.label}</span><span>{item.value}%</span></div>
                                <div className="h-2 overflow-hidden rounded-full bg-[#1f2a3d]"><motion.div className="h-full rounded-full bg-linear-to-r from-[#58a6ff] to-[#79c0ff]" initial={{ width: 0 }} animate={{ width: `${item.value}%` }} transition={{ duration: 0.8, ease: 'easeOut' }} /></div>
                              </div>
                            ))}
                          </div>
                          <div className="mt-4 grid grid-cols-2 gap-3 border-t border-[#2a3344] pt-3 text-xs">
                            <div><div className="text-[#8b949e]">Conventional commits</div><div className="font-semibold text-white">{formatPercent(result.snapshot?.git?.conventionalCommitRate ?? 0)}</div></div>
                            <div><div className="text-[#8b949e]">Contributors</div><div className="font-semibold text-white">{result.snapshot?.git?.contributors ?? 0}</div></div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                    <div className={CARD_CLASS}>
                      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><BookOpen className="h-4 w-4 text-[#58a6ff]" />Summary</div>
                      <p className="text-sm leading-relaxed text-[#c9d1d9]">{result.summary || 'No summary available.'}</p>
                      <div className="mt-4 flex flex-wrap gap-2">
                        {getSummaryHighlights(result.summary).map((snippet) => (
                          <span key={snippet} className="rounded-full border border-[#2a3344] bg-surface-2 px-3 py-1 text-xs text-[#c9d1d9]">{snippet}</span>
                        ))}
                      </div>
                    </div>

                    <div className={CARD_CLASS}>
                      <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white"><GitBranch className="h-4 w-4 text-[#58a6ff]" />Professional Roadmap</div>
                      <ol className="relative space-y-4 border-l border-[#2a3344] pl-5">
                        {(result.roadmap ?? []).map((step, idx) => (
                          <li key={`${step}-${idx}`} className="relative">
                            <span className="absolute -left-7 top-0 flex h-4 w-4 items-center justify-center rounded-full border border-[#58a6ff] bg-background text-[10px] text-[#79c0ff]">{idx + 1}</span>
                            <div className="rounded-lg border border-[#2a3344] bg-surface-2 px-3 py-2 text-sm leading-relaxed text-[#c9d1d9]">{step}</div>
                          </li>
                        ))}
                      </ol>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                    <div className={CARD_CLASS}>
                      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><FolderTree className="h-4 w-4 text-[#58a6ff]" />Repository Structure</div>
                      <div className="mb-4 grid grid-cols-2 gap-3 text-xs">
                        <div className="rounded-lg border border-[#2a3344] bg-surface-2 p-3"><div className="text-[#8b949e]">Files</div><div className="mt-1 font-semibold text-white">{result.snapshot?.files?.fileCount ?? 0}</div></div>
                        <div className="rounded-lg border border-[#2a3344] bg-surface-2 p-3"><div className="text-[#8b949e]">Directories</div><div className="mt-1 font-semibold text-white">{result.snapshot?.files?.directoryCount ?? 0}</div></div>
                      </div>
                      <div className="space-y-2">
                        {topLevelList.map(([name, count]) => (
                          <div key={name} className="flex items-center justify-between rounded-md border border-[#2a3344] bg-surface-2 px-3 py-2 text-xs text-[#c9d1d9]"><span>{name}</span><span className="font-semibold text-white">{count}</span></div>
                        ))}
                      </div>
                    </div>

                    <div className={CARD_CLASS}>
                      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><Shield className="h-4 w-4 text-[#58a6ff]" />Tooling and Compliance</div>
                      <div className="grid grid-cols-2 gap-2">
                        {toolingSignals.map((signal) => (
                          <div key={signal.label} className={`rounded-lg border px-3 py-2 text-xs ${signal.active ? 'border-[#2e7d47] bg-[#1f6f3a]/20 text-[#8ad8ab]' : 'border-[#5f2120] bg-[#7f1d1d]/20 text-[#fca5a5]'}`}>
                            {signal.label}: {signal.active ? 'Present' : 'Missing'}
                          </div>
                        ))}
                      </div>

                    </div>
                  </div>

                  <div className={`${CARD_CLASS} flex items-start gap-3`}>
                    <Info className="mt-0.5 h-4 w-4 text-[#79c0ff]" />
                    <div className="text-xs text-[#8b949e]">Run this analysis after major commits and releases to track trend changes and confidence over time.</div>
                  </div>
                </motion.div>
              ) : null}
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  )
}
