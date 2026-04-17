"use client"

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isSocialSubmitting, setIsSocialSubmitting] = useState(false)
  const [error, setError] = useState('')

  const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'
  const githubClientId = process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID || ''
  const googleClientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || ''
  const redirectUri = useMemo(() => {
    if (typeof window === 'undefined') return ''
    return `${window.location.origin}/login`
  }, [])

  const persistAuth = (data: { token: string; id: string; username: string; email: string }) => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('gitguard_token', data.token)
      localStorage.setItem(
        'gitguard_user',
        JSON.stringify({ id: data.id, username: data.username, email: data.email })
      )
    }
  }

  const handleSocialResponse = async (endpoint: string, payload: Record<string, unknown>) => {
    setError('')
    setIsSocialSubmitting(true)
    try {
      const response = await fetch(`${apiBase}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      })

      const data = await response.json().catch(() => ({}))
      if (!response.ok) {
        setError(data?.message || 'Social sign-in failed.')
        return
      }

      persistAuth(data)
      router.push('/analyze')
    } catch {
      setError('Unable to reach the server for social sign-in.')
    } finally {
      setIsSocialSubmitting(false)
    }
  }

  useEffect(() => {
    if (typeof window === 'undefined') return

    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state')
    const emailFromQuery = params.get('email')
    const passwordFromQuery = params.get('password')

    if (emailFromQuery || passwordFromQuery) {
      if (emailFromQuery) setEmail(emailFromQuery)
      if (passwordFromQuery) setPassword(passwordFromQuery)
      window.history.replaceState({}, document.title, '/login')
    }

    if (code && state === 'github') {
      handleSocialResponse('/api/auth/github', { code, redirectUri })
      window.history.replaceState({}, document.title, '/login')
      return
    }

    const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const accessToken = hashParams.get('access_token')
    const tokenState = hashParams.get('state')
    if (accessToken && tokenState === 'google') {
      handleSocialResponse('/api/auth/google', { access_token: accessToken })
      window.history.replaceState({}, document.title, '/login')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [redirectUri, router])

  const startGithubSignIn = () => {
    if (!githubClientId) {
      setError('GitHub sign-in is not configured. Set NEXT_PUBLIC_GITHUB_CLIENT_ID in client env.')
      return
    }

    const authUrl = new URL('https://github.com/login/oauth/authorize')
    authUrl.searchParams.set('client_id', githubClientId)
    authUrl.searchParams.set('redirect_uri', redirectUri)
    authUrl.searchParams.set('scope', 'read:user user:email')
    authUrl.searchParams.set('state', 'github')
    window.location.href = authUrl.toString()
  }

  const startGoogleSignIn = () => {
    if (!googleClientId) {
      setError('Google sign-in is not configured. Set NEXT_PUBLIC_GOOGLE_CLIENT_ID in client env.')
      return
    }

    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth')
    authUrl.searchParams.set('client_id', googleClientId)
    authUrl.searchParams.set('redirect_uri', redirectUri)
    authUrl.searchParams.set('response_type', 'token')
    authUrl.searchParams.set('scope', 'openid email profile')
    authUrl.searchParams.set('state', 'google')
    authUrl.searchParams.set('prompt', 'select_account')
    window.location.href = authUrl.toString()
  }

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

      persistAuth(data)

      router.push('/analyze')
    } catch {
      setError('Unable to reach the server. Please check backend connectivity.')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <main className="min-h-screen bg-linear-to-br from-blue-50 via-white to-slate-100 px-4 py-12 sm:px-6 lg:px-8">
      <div className="mx-auto flex min-h-[calc(100vh-6rem)] w-full max-w-6xl items-center justify-center">
        <section className="grid w-full overflow-hidden rounded-3xl border border-blue-100 bg-white shadow-[0_20px_80px_rgba(0,60,140,0.14)] lg:grid-cols-2">
          <div className="hidden bg-linear-to-br from-blue-700 via-blue-600 to-cyan-500 p-10 text-white lg:flex lg:flex-col lg:justify-between">
            <div>
              <p className="inline-flex rounded-full border border-white/30 px-3 py-1 text-xs font-semibold tracking-[0.18em]">
                GITGUARD ACCESS
              </p>
              <h1 className="mt-6 text-4xl font-bold leading-tight">
                Welcome back to your security workspace.
              </h1>
              <p className="mt-4 max-w-md text-blue-100">
                Continue scanning repositories, review malware risk verdicts, and monitor critical alerts from one place.
              </p>
            </div>
            <p className="text-sm text-blue-100">Protecting open-source workflows, one scan at a time.</p>
          </div>

          <div className="p-7 sm:p-10 lg:p-12">
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-blue-600">Sign In</p>
            <h2 className="mt-3 text-3xl font-bold text-slate-900">Log in to GitGuard</h2>
            <p className="mt-2 text-sm text-slate-600">
              Do not have an account?{' '}
              <Link href="/signup" className="font-semibold text-blue-600 hover:text-blue-700">
                Create one
              </Link>
            </p>

            <form className="mt-8 space-y-5" method="post" action="/login" onSubmit={handleSubmit}>
              <div>
                <label htmlFor="email" className="mb-2 block text-sm font-medium text-slate-800">
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
                  className="w-full rounded-xl border border-slate-300 px-4 py-3 text-slate-900 outline-none transition focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
                  placeholder="you@company.com"
                />
              </div>

              <div>
                <div className="mb-2 flex items-center justify-between">
                  <label htmlFor="password" className="block text-sm font-medium text-slate-800">
                    Password
                  </label>
                  <Link href="#" className="text-sm font-medium text-blue-600 hover:text-blue-700">
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
                  className="w-full rounded-xl border border-slate-300 px-4 py-3 text-slate-900 outline-none transition focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
                  placeholder="Enter your password"
                />
              </div>

              {error && (
                <p className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
              )}

              <label className="flex items-center gap-3 text-sm text-slate-700">
                <input type="checkbox" name="remember" className="h-4 w-4 rounded border-slate-300 text-blue-600" />
                Keep me signed in
              </label>

              <button
                type="submit"
                disabled={isSubmitting || isSocialSubmitting}
                className="w-full rounded-xl bg-blue-600 px-4 py-3 text-base font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isSubmitting ? 'Signing in...' : 'Log In'}
              </button>

              <div className="relative py-1">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-slate-200"></div>
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-white px-3 text-slate-500">Or continue with</span>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={startGoogleSignIn}
                  disabled={isSubmitting || isSocialSubmitting}
                  className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <span className="text-base">G</span>
                  Google
                </button>

                <button
                  type="button"
                  onClick={startGithubSignIn}
                  disabled={isSubmitting || isSocialSubmitting}
                  className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <span className="inline-flex h-5 w-5 items-center justify-center rounded bg-slate-900 text-xs font-bold text-white">GH</span>
                  GitHub
                </button>
              </div>
            </form>
          </div>
        </section>
      </div>
    </main>
  )
}
