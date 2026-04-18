"use client"

import { useEffect, useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { getAuthToken, setAuthSession, validateAuthSession } from '@/lib/authSession'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState('')

  const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'
  const validatedApiBase = apiBase

  useEffect(() => {
    if (typeof window === 'undefined') return

    const checkSession = async () => {
      const currentToken = getAuthToken()
      if (!currentToken) return

      const valid = await validateAuthSession(validatedApiBase)
      if (valid) {
        router.replace('/analyze')
      }
    }
    checkSession()
  }, [router, validatedApiBase])

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setError('')

    if (!email.trim() || !password.trim()) {
      setError('Email and password are required.')
      return
    }

    try {
      setIsSubmitting(true)

      const response = await fetch(`${apiBase}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email.trim().toLowerCase(),
          password,
        }),
      })

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        setError(data?.message || 'Login failed. Please try again.')
        return
      }

      setAuthSession(data)

      const params = new URLSearchParams(window.location.search)
      const nextTarget = params.get('next')
      const redirectTo = nextTarget && nextTarget.startsWith('/') ? nextTarget : '/analyze'
      router.push(redirectTo)
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
        <div className="absolute -left-20 top-1/3 h-72 w-72 rounded-full bg-cyan-500/15 blur-[110px]" />
      </div>
      <div className="mx-auto flex min-h-[calc(100vh-6rem)] w-full max-w-6xl items-center justify-center">
        <section className="relative grid w-full overflow-hidden rounded-3xl border border-blue-400/20 bg-linear-to-br from-white/8 via-white/5 to-white/3 shadow-[0_24px_90px_rgba(9,20,50,0.5)] backdrop-blur-xl lg:grid-cols-2">
          <div className="hidden bg-linear-to-br from-[#0a1935] via-[#0f2c5f] to-[#134286] p-10 text-white lg:flex lg:flex-col lg:justify-between">
            <div>
              <p className="inline-flex rounded-full border border-blue-300/35 bg-blue-400/10 px-3 py-1 text-xs font-semibold tracking-[0.18em] text-blue-100">
                GITGUARD ACCESS
              </p>
              <h1
                className="mt-6 text-4xl font-bold leading-tight"
                style={{ fontFamily: 'var(--font-black-ops-one)' }}
              >
                Welcome back to your security workspace.
              </h1>
              <p className="mt-4 max-w-md text-blue-100/90">
                Continue scanning repositories, review malware risk verdicts, and monitor critical alerts from one place.
              </p>
            </div>
            <p className="text-sm text-blue-100/85">Protecting open-source workflows, one scan at a time.</p>
          </div>

          <div className="p-7 sm:p-10 lg:p-12">
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-blue-300">Sign In</p>
            <h2
              className="mt-3 text-3xl font-bold text-white"
              style={{ fontFamily: 'var(--font-black-ops-one)' }}
            >
              Log in to GitGuard
            </h2>
            <p className="mt-2 text-sm text-slate-300">
              Do not have an account?{' '}
              <Link href="/signup" className="font-semibold text-blue-300 hover:text-blue-200">
                Create one
              </Link>
            </p>

            <form className="mt-8 space-y-5" onSubmit={handleSubmit}>
              <div>
                <label htmlFor="email" className="mb-2 block text-sm font-medium text-slate-200">
                  Email address
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
                <div className="mb-2 flex items-center justify-between">
                  <label htmlFor="password" className="block text-sm font-medium text-slate-200">
                    Password
                  </label>
                  <Link href="#" className="text-sm font-medium text-blue-300 hover:text-blue-200">
                    Forgot password?
                  </Link>
                </div>
                <input
                  id="password"
                  name="password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  autoComplete="current-password"
                  className="w-full rounded-xl border border-blue-300/25 bg-[#0b1730]/70 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-400 focus:border-blue-400 focus:ring-4 focus:ring-blue-500/20"
                  placeholder="Enter your password"
                />
              </div>

              {error && (
                <p className="rounded-lg border border-red-500/35 bg-red-500/12 px-3 py-2 text-sm text-red-200">{error}</p>
              )}

              <label className="flex items-center gap-3 text-sm text-slate-300">
                <input type="checkbox" name="remember" className="h-4 w-4 rounded border-blue-300/30 bg-[#0b1730]/70 text-blue-400" />
                Keep me signed in
              </label>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full rounded-xl border border-blue-300/45 bg-linear-to-r from-blue-600 to-blue-500 px-4 py-3 text-base font-semibold text-white shadow-[0_10px_28px_rgba(37,99,235,0.4)] transition hover:from-blue-500 hover:to-blue-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isSubmitting ? 'Signing in...' : 'Log In'}
              </button>
            </form>
          </div>
        </section>
      </div>
    </main>
  )
}
