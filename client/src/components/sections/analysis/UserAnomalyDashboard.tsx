'use client'

import { useMemo, useState, useSyncExternalStore } from 'react'
import { useRouter } from 'next/navigation'
import Header from '@/components/layout/Header'
import Footer from '@/components/layout/Footer'
import Button from '@/components/ui/Button'
import { clearAuthSession, getAuthToken } from '@/lib/authSession'
import { getApiBaseUrl } from '@/lib/apiBase'

type RepoContribution = {
  repo?: string
  count?: number
}

type UserAnomalyResponse = {
  username?: string
  lookbackDays?: number
  since?: string
  account?: {
    id?: number
    login?: string
    createdAt?: string
    publicRepos?: number
    followers?: number
    following?: number
  }
  anomalyProfile?: {
    score?: number
    riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | string
    reasons?: string[]
    profileSummary?: {
      accountAgeDays?: number
      eventsAnalyzed?: number
      activeDays?: number
      pushEvents?: number
      uniqueReposTouched?: number
    }
    activityMetrics?: {
      nightActivityRatio?: number
      weekendActivityRatio?: number
      burstDays?: number
      burstDayRatio?: number
    }
    contributionMetrics?: {
      totalCommitsAnalyzed?: number
      dominantRepoContributionRatio?: number
      suspiciousMessageRatio?: number
      shortMessageRatio?: number
      forcePushEventRatio?: number
    }
    topContributionRepos?: RepoContribution[]
    lookbackDays?: number
  }
}

function safeNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value))
}

function pct(value: number): number {
  return clamp(Math.round(value * 100), 0, 100)
}

function formatDate(isoDate?: string): string {
  if (!isoDate) return '-'
  const date = new Date(isoDate)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleDateString()
}

function normalizeRiskLevel(level: string): 'LOW' | 'MEDIUM' | 'HIGH' {
  if (level === 'HIGH') return 'HIGH'
  if (level === 'MEDIUM') return 'MEDIUM'
  return 'LOW'
}

function getRiskTone(level: 'LOW' | 'MEDIUM' | 'HIGH'): {
  chip: string
  panel: string
  meter: string
} {
  if (level === 'HIGH') {
    return {
      chip: 'bg-rose-500/20 text-rose-100 border-rose-300/40',
      panel: 'border-rose-300/20 bg-rose-500/10',
      meter: 'from-rose-400 via-orange-400 to-red-400',
    }
  }

  if (level === 'MEDIUM') {
    return {
      chip: 'bg-amber-500/20 text-amber-100 border-amber-300/40',
      panel: 'border-amber-300/20 bg-amber-500/10',
      meter: 'from-amber-300 via-yellow-300 to-orange-300',
    }
  }

  return {
    chip: 'bg-emerald-500/20 text-emerald-100 border-emerald-300/40',
    panel: 'border-emerald-300/20 bg-emerald-500/10',
    meter: 'from-emerald-300 via-teal-300 to-cyan-300',
  }
}

export default function UserAnomalyDashboard() {
  const router = useRouter()
  const [usernameInput, setUsernameInput] = useState('')
  const [lookbackDays, setLookbackDays] = useState(45)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<UserAnomalyResponse | null>(null)

  const apiBase = getApiBaseUrl()
  const authToken = useSyncExternalStore(
    () => () => undefined,
    () => getAuthToken(),
    () => null,
  )

  const anomalyScore = safeNumber(result?.anomalyProfile?.score, 0)
  const riskLevel = normalizeRiskLevel(
    typeof result?.anomalyProfile?.riskLevel === 'string' ? result.anomalyProfile.riskLevel : 'LOW',
  )
  const riskTone = getRiskTone(riskLevel)

  const activityMetrics = result?.anomalyProfile?.activityMetrics
  const contributionMetrics = result?.anomalyProfile?.contributionMetrics
  const profileSummary = result?.anomalyProfile?.profileSummary

  const timelineRiskBars = useMemo(() => {
    const nightRatio = safeNumber(activityMetrics?.nightActivityRatio, 0)
    const weekendRatio = safeNumber(activityMetrics?.weekendActivityRatio, 0)
    const burstRatio = safeNumber(activityMetrics?.burstDayRatio, 0)

    return [
      {
        label: 'Night activity',
        description: 'Share of actions at night UTC',
        percent: pct(nightRatio),
      },
      {
        label: 'Weekend activity',
        description: 'Share of actions on weekends',
        percent: pct(weekendRatio),
      },
      {
        label: 'Burst activity',
        description: 'Days with compressed high activity',
        percent: pct(burstRatio),
      },
    ]
  }, [activityMetrics?.nightActivityRatio, activityMetrics?.weekendActivityRatio, activityMetrics?.burstDayRatio])

  const contributionRiskBars = useMemo(() => {
    const dominant = safeNumber(contributionMetrics?.dominantRepoContributionRatio, 0)
    const suspiciousMsg = safeNumber(contributionMetrics?.suspiciousMessageRatio, 0)
    const shortMsg = safeNumber(contributionMetrics?.shortMessageRatio, 0)
    const forcePush = safeNumber(contributionMetrics?.forcePushEventRatio, 0)

    return [
      {
        label: 'Dominant repo concentration',
        percent: pct(dominant),
      },
      {
        label: 'Suspicious commit messages',
        percent: pct(suspiciousMsg),
      },
      {
        label: 'Very short commit messages',
        percent: pct(shortMsg),
      },
      {
        label: 'Force-push behavior signal',
        percent: pct(forcePush),
      },
    ]
  }, [
    contributionMetrics?.dominantRepoContributionRatio,
    contributionMetrics?.suspiciousMessageRatio,
    contributionMetrics?.shortMessageRatio,
    contributionMetrics?.forcePushEventRatio,
  ])

  const rawTopRepos = Array.isArray(result?.anomalyProfile?.topContributionRepos)
    ? result.anomalyProfile.topContributionRepos
    : []
  const topContributionRepos = rawTopRepos
    .map((item) => ({
      repo: typeof item?.repo === 'string' && item.repo.trim() ? item.repo : 'unknown',
      count: safeNumber(item?.count, 0),
    }))
    .filter((item) => item.count > 0)
    .slice(0, 8)

  const maxRepoContribution = useMemo(() => {
    const max = topContributionRepos.reduce((carry, item) => Math.max(carry, item.count), 0)
    return Math.max(max, 1)
  }, [topContributionRepos])

  const runAnalysis = async () => {
    setError('')
    setResult(null)

    const cleanedInput = usernameInput.trim()
    if (!cleanedInput) {
      setError('Please provide a GitHub username or profile URL.')
      return
    }

    const token = getAuthToken()
    if (!token) {
      router.push('/login')
      return
    }

    try {
      setIsLoading(true)

      const response = await fetch(`${apiBase}/api/repo/user-anomaly-profile`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          input: cleanedInput,
          lookbackDays: clamp(Math.floor(lookbackDays), 7, 180),
        }),
      })

      const payload = (await response.json().catch(() => ({}))) as UserAnomalyResponse & { message?: string }

      if (!response.ok) {
        if (response.status === 401) {
          clearAuthSession()
          router.push('/login')
          return
        }

        setError(payload?.message || 'Unable to analyze user profile right now.')
        return
      }

      setResult(payload)
    } catch {
      setError('Unable to reach backend. Verify server is running and CORS is enabled.')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-linear-to-br from-blue-950 via-slate-950 to-black text-slate-100">
      <Header />

      <main className="py-16">
        <section className="container mx-auto px-4">
          <div className="mx-auto max-w-6xl space-y-8">
            <div className="text-center">
              <div className="mb-6 inline-flex items-center justify-center">
                <div className="h-px w-20 bg-white/20"></div>
                <h1 className="px-6 text-2xl font-semibold uppercase tracking-wider text-cyan-200">User Anomaly Profile</h1>
                <div className="h-px w-20 bg-white/20"></div>
              </div>
              <h2 className="mb-4 text-3xl font-bold text-white md:text-4xl">Account Activity & Commit Risk Detection</h2>
              <p className="mx-auto max-w-3xl text-lg text-blue-100">
                Analyze suspicious behavior based on account age, contribution patterns, and recent public commit activity.
              </p>
            </div>

            <section className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-xl backdrop-blur-md md:p-8">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
                <input
                  type="text"
                  value={usernameInput}
                  onChange={(event) => setUsernameInput(event.target.value)}
                  placeholder="github username or profile URL"
                  className="md:col-span-3 w-full rounded-lg border border-white/20 bg-black/30 px-4 py-3 text-white placeholder:text-blue-200/70 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-500/40"
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') {
                      event.preventDefault()
                      runAnalysis()
                    }
                  }}
                />

                <input
                  type="number"
                  value={lookbackDays}
                  min={7}
                  max={180}
                  onChange={(event) => setLookbackDays(safeNumber(Number(event.target.value), 45))}
                  className="md:col-span-1 w-full rounded-lg border border-white/20 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-500/40"
                />

                <Button
                  onClick={runAnalysis}
                  disabled={isLoading || !usernameInput.trim() || !authToken}
                  className="md:col-span-1 w-full"
                >
                  {isLoading ? 'Analyzing...' : 'Run Profile Scan'}
                </Button>
              </div>

              <p className="mt-3 text-xs text-slate-300">Lookback range: 7 to 180 days</p>

              {!authToken && (
                <p className="mt-4 rounded-xl border border-yellow-300/30 bg-yellow-500/10 px-4 py-2 text-sm text-yellow-100">
                  You are not logged in. Please sign in first.
                </p>
              )}

              {error && (
                <p className="mt-4 rounded-xl border border-red-300/30 bg-red-500/10 px-4 py-2 text-sm text-red-100">{error}</p>
              )}
            </section>

            {isLoading && (
              <section className="rounded-2xl border border-white/10 bg-white/5 p-10 shadow-xl">
                <div className="flex items-center justify-center gap-4 text-blue-100">
                  <div className="h-8 w-8 animate-spin rounded-full border-4 border-blue-200 border-t-blue-600"></div>
                  <p className="text-lg font-medium">Collecting profile activity and commit contribution signals...</p>
                </div>
              </section>
            )}

            {result && (
              <section className="space-y-6 rounded-3xl border border-white/10 bg-linear-to-b from-white/5 via-white/2.5 to-transparent p-4 md:p-6 backdrop-blur-sm">
                <article className={`rounded-2xl border p-5 ${riskTone.panel}`}>
                  <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                    <div>
                      <p className="text-sm uppercase tracking-[0.22em] text-blue-100/80">Anomaly Profile Overview</p>
                      <h3 className="mt-1 text-2xl font-bold text-white">GitHub User: {result.username || '-'}</h3>
                      <p className="mt-2 text-sm text-blue-100/90">
                        Account created on {formatDate(result?.account?.createdAt)} • Lookback {safeNumber(result?.lookbackDays, 45)} days •
                        Since {formatDate(result?.since)}
                      </p>
                    </div>
                    <span className={`inline-flex h-fit rounded-xl border px-3 py-1 text-sm font-semibold ${riskTone.chip}`}>
                      Risk Level: {riskLevel}
                    </span>
                  </div>
                </article>

                <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
                  <article className="rounded-2xl border border-white/12 bg-black/35 p-5">
                    <h4 className="text-lg font-semibold text-slate-100">Anomaly Score</h4>
                    <div className="mt-4 h-4 w-full overflow-hidden rounded-full bg-slate-800">
                      <div
                        className={`h-full rounded-full bg-linear-to-r ${riskTone.meter}`}
                        style={{ width: `${Math.max(5, anomalyScore)}%` }}
                      ></div>
                    </div>
                    <p className="mt-3 text-4xl font-bold text-white">{anomalyScore}</p>
                    <p className="text-sm text-slate-300">Score out of 100</p>
                  </article>

                  <article className="rounded-2xl border border-white/12 bg-black/35 p-5">
                    <p className="text-sm text-slate-300">Account Age</p>
                    <p className="mt-1 text-3xl font-bold text-cyan-200">{safeNumber(profileSummary?.accountAgeDays, 0)}</p>
                    <p className="text-xs text-slate-400">days since profile creation</p>

                    <p className="mt-4 text-sm text-slate-300">Public Repositories</p>
                    <p className="mt-1 text-2xl font-semibold text-white">{safeNumber(result?.account?.publicRepos, 0)}</p>

                    <p className="mt-4 text-sm text-slate-300">Followers / Following</p>
                    <p className="mt-1 text-2xl font-semibold text-white">
                      {safeNumber(result?.account?.followers, 0)} / {safeNumber(result?.account?.following, 0)}
                    </p>
                  </article>

                  <article className="rounded-2xl border border-white/12 bg-black/35 p-5">
                    <p className="text-sm text-slate-300">Events Analyzed</p>
                    <p className="mt-1 text-3xl font-bold text-white">{safeNumber(profileSummary?.eventsAnalyzed, 0)}</p>

                    <p className="mt-4 text-sm text-slate-300">Active Days</p>
                    <p className="mt-1 text-2xl font-semibold text-cyan-200">{safeNumber(profileSummary?.activeDays, 0)}</p>

                    <p className="mt-4 text-sm text-slate-300">Push Events</p>
                    <p className="mt-1 text-2xl font-semibold text-white">{safeNumber(profileSummary?.pushEvents, 0)}</p>

                    <p className="mt-4 text-sm text-slate-300">Unique Repos Touched</p>
                    <p className="mt-1 text-2xl font-semibold text-white">{safeNumber(profileSummary?.uniqueReposTouched, 0)}</p>
                  </article>
                </div>

                <div className="grid grid-cols-1 gap-5 lg:grid-cols-5">
                  <article className="rounded-2xl border border-white/12 bg-black/35 p-5 lg:col-span-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-lg font-semibold text-slate-100">Activity Behavior Signals</h4>
                      <span className="rounded-lg border border-white/15 px-2 py-1 text-xs text-slate-300">Time-pattern view</span>
                    </div>

                    <div className="mt-4 space-y-3">
                      {timelineRiskBars.map((item) => (
                        <div key={item.label} className="rounded-lg border border-white/10 bg-white/3 p-3">
                          <div className="mb-2 flex items-center justify-between text-sm text-slate-200">
                            <span>{item.label}</span>
                            <span>{item.percent}%</span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                            <div className="h-full rounded-full bg-linear-to-r from-cyan-400 via-blue-400 to-indigo-300" style={{ width: `${Math.max(8, item.percent)}%` }}></div>
                          </div>
                          <p className="mt-1 text-xs text-slate-400">{item.description}</p>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className="rounded-2xl border border-white/12 bg-black/35 p-5 lg:col-span-2">
                    <h4 className="text-lg font-semibold text-slate-100">Detected Reasons</h4>
                    {Array.isArray(result?.anomalyProfile?.reasons) && result.anomalyProfile.reasons.length > 0 ? (
                      <ul className="mt-3 space-y-2">
                        {result.anomalyProfile.reasons.map((reason) => (
                          <li key={reason} className="rounded-lg border border-white/10 bg-white/3 px-3 py-2 text-sm text-slate-200">
                            {reason}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-3 text-sm text-slate-400">No explicit anomaly reasons were triggered.</p>
                    )}
                  </article>
                </div>

                <div className="grid grid-cols-1 gap-5 lg:grid-cols-5">
                  <article className="rounded-2xl border border-white/12 bg-black/35 p-5 lg:col-span-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-lg font-semibold text-slate-100">Contribution Pattern Signals</h4>
                      <span className="rounded-lg border border-white/15 px-2 py-1 text-xs text-slate-300">Commit-pattern view</span>
                    </div>

                    <div className="mt-4 space-y-3">
                      {contributionRiskBars.map((item) => (
                        <div key={item.label} className="rounded-lg border border-white/10 bg-white/3 p-3">
                          <div className="mb-2 flex items-center justify-between text-sm text-slate-200">
                            <span>{item.label}</span>
                            <span>{item.percent}%</span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                            <div className="h-full rounded-full bg-linear-to-r from-amber-300 via-orange-300 to-rose-300" style={{ width: `${Math.max(8, item.percent)}%` }}></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className="rounded-2xl border border-white/12 bg-black/35 p-5 lg:col-span-2">
                    <h4 className="text-lg font-semibold text-slate-100">Commit Metrics Snapshot</h4>
                    <div className="mt-3 grid grid-cols-1 gap-3">
                      <div className="rounded-lg border border-white/10 bg-white/3 p-3">
                        <p className="text-xs uppercase tracking-wide text-slate-400">Commits Analyzed</p>
                        <p className="mt-1 text-2xl font-semibold text-slate-100">{safeNumber(contributionMetrics?.totalCommitsAnalyzed, 0)}</p>
                      </div>
                      <div className="rounded-lg border border-white/10 bg-white/3 p-3">
                        <p className="text-xs uppercase tracking-wide text-slate-400">Burst Days</p>
                        <p className="mt-1 text-2xl font-semibold text-slate-100">{safeNumber(activityMetrics?.burstDays, 0)}</p>
                      </div>
                    </div>
                  </article>
                </div>

                <article className="rounded-2xl border border-white/12 bg-black/35 p-5">
                  <h4 className="text-lg font-semibold text-slate-100">Top Contribution Repositories</h4>
                  {topContributionRepos.length === 0 ? (
                    <p className="mt-3 text-sm text-slate-400">No commit repository distribution was available in this window.</p>
                  ) : (
                    <div className="mt-4 space-y-3">
                      {topContributionRepos.map((item) => {
                        const width = Math.max(10, Math.round((item.count / maxRepoContribution) * 100))
                        return (
                          <div key={item.repo} className="rounded-lg border border-white/10 bg-white/3 p-3">
                            <div className="mb-2 flex items-center justify-between text-sm text-slate-200">
                              <span className="truncate pr-3">{item.repo}</span>
                              <span>{item.count}</span>
                            </div>
                            <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                              <div className="h-full rounded-full bg-cyan-400" style={{ width: `${width}%` }}></div>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </article>
              </section>
            )}
          </div>
        </section>
      </main>

      <Footer />
    </div>
  )
}
