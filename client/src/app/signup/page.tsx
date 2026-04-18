"use client"

import { useEffect, useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { getAuthToken, setAuthSession } from '@/lib/authSession'
import { getApiBaseUrl } from '@/lib/apiBase'

export default function SignUpPage() {
  const router = useRouter()
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState('')

  const apiBase = getApiBaseUrl()

  useEffect(() => {
    const token = getAuthToken()
    if (token) {
      router.replace('/analyze')
    }
  }, [router])

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setError('')

    const normalizedName = fullName.trim()
    const normalizedEmail = email.trim().toLowerCase()

    if (!normalizedName || !normalizedEmail || !password) {
      setError('Full name, email, and password are required.')
      return
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters long.')
      return
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    try {
      setIsSubmitting(true)

      const response = await fetch(`${apiBase}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: normalizedName,
          email: normalizedEmail,
          password,
        }),
      })

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        setError(data?.message || 'Unable to create account. Please try again.')
        return
      }

      setAuthSession(data)

      router.push('/analyze')
    } catch {
      setError('Unable to reach the server. Please check backend connectivity.')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-linear-to-br from-[#060b18] via-[#0b1220] to-[#19153a] px-4 py-12 sm:px-6 lg:px-8">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-0 h-[28rem] w-[28rem] -translate-x-1/2 rounded-full bg-blue-500/25 blur-[120px]" />
        <div className="absolute right-0 top-1/3 h-72 w-72 rounded-full bg-cyan-500/15 blur-[110px]" />
      </div>
      <div className="mx-auto flex min-h-[calc(100vh-6rem)] w-full max-w-6xl items-center justify-center">
        <section className="relative grid w-full overflow-hidden rounded-3xl border border-blue-400/20 bg-linear-to-br from-white/8 via-white/5 to-white/3 shadow-[0_24px_90px_rgba(9,20,50,0.5)] backdrop-blur-xl lg:grid-cols-2">
          <div className="hidden bg-linear-to-br from-[#0a1935] via-[#0f2c5f] to-[#134286] p-10 text-white lg:flex lg:flex-col lg:justify-between">
            <div>
              <p className="inline-flex rounded-full border border-blue-300/35 bg-blue-400/10 px-3 py-1 text-xs font-semibold tracking-[0.18em] text-blue-100">
                GITGUARD ONBOARDING
              </p>
              <h1
                className="mt-6 text-4xl font-bold leading-tight"
                style={{ fontFamily: 'var(--font-black-ops-one)' }}
              >
                Create your security account in minutes.
              </h1>
              <p className="mt-4 max-w-md text-blue-100/90">
                Start detecting suspicious repositories with deterministic malware verdicts and team-ready reporting.
              </p>
            </div>
            <p className="text-sm text-blue-100/85">Built for secure development teams and security engineers.</p>
          </div>

          <div className="p-7 sm:p-10 lg:p-12">
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-blue-300">Sign Up</p>
            <h2
              className="mt-3 text-3xl font-bold text-white"
              style={{ fontFamily: 'var(--font-black-ops-one)' }}
            >
              Create your GitGuard account
            </h2>
            <p className="mt-2 text-sm text-slate-300">
              Already registered?{' '}
              <Link href="/login" className="font-semibold text-blue-300 hover:text-blue-200">
                Log in
              </Link>
            </p>

            <form className="mt-8 space-y-5" onSubmit={handleSubmit}>
              <div>
                <label htmlFor="fullName" className="mb-2 block text-sm font-medium text-slate-200">
                  Full name
                </label>
                <input
                  id="fullName"
                  name="fullName"
                  type="text"
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                  required
                  autoComplete="name"
                  className="w-full rounded-xl border border-blue-300/25 bg-[#0b1730]/70 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-400 focus:border-blue-400 focus:ring-4 focus:ring-blue-500/20"
                  placeholder="Alex Johnson"
                />
              </div>

              <div>
                <label htmlFor="email" className="mb-2 block text-sm font-medium text-slate-200">
                  Work email
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                  autoComplete="email"
                  className="w-full rounded-xl border border-blue-300/25 bg-[#0b1730]/70 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-400 focus:border-blue-400 focus:ring-4 focus:ring-blue-500/20"
                  placeholder="you@company.com"
                />
              </div>

              <div>
                <label htmlFor="password" className="mb-2 block text-sm font-medium text-slate-200">
                  Password
                </label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  autoComplete="new-password"
                  className="w-full rounded-xl border border-blue-300/25 bg-[#0b1730]/70 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-400 focus:border-blue-400 focus:ring-4 focus:ring-blue-500/20"
                  placeholder="At least 8 characters"
                />
              </div>

              <div>
                <label htmlFor="confirmPassword" className="mb-2 block text-sm font-medium text-slate-200">
                  Confirm password
                </label>
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  required
                  autoComplete="new-password"
                  className="w-full rounded-xl border border-blue-300/25 bg-[#0b1730]/70 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-400 focus:border-blue-400 focus:ring-4 focus:ring-blue-500/20"
                  placeholder="Re-enter your password"
                />
              </div>

              {error && (
                <p className="rounded-lg border border-red-500/35 bg-red-500/12 px-3 py-2 text-sm text-red-200">{error}</p>
              )}

              <label className="flex items-start gap-3 text-sm text-slate-300">
                <input type="checkbox" name="terms" required className="mt-1 h-4 w-4 rounded border-blue-300/30 bg-[#0b1730]/70 text-blue-400" />
                <span>
                  I agree to the{' '}
                  <Link href="#" className="font-medium text-blue-300 hover:text-blue-200">
                    Terms
                  </Link>{' '}
                  and{' '}
                  <Link href="#" className="font-medium text-blue-300 hover:text-blue-200">
                    Privacy Policy
                  </Link>
                  .
                </span>
              </label>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full rounded-xl border border-blue-300/45 bg-linear-to-r from-blue-600 to-blue-500 px-4 py-3 text-base font-semibold text-white shadow-[0_10px_28px_rgba(37,99,235,0.4)] transition hover:from-blue-500 hover:to-blue-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isSubmitting ? 'Creating account...' : 'Create Account'}
              </button>
            </form>
          </div>
        </section>
      </div>
    </main>
  )
}
