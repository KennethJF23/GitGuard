'use client'

import { useEffect, useMemo, useState, type PropsWithChildren } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { getAuthToken, validateAuthSession } from '@/lib/authSession'
import { getApiBaseUrl } from '@/lib/apiBase'

const AUTH_PAGES = ['/login', '/signup']
const PUBLIC_ROUTES = ['/', ...AUTH_PAGES]

function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some((route) => pathname === route || pathname.startsWith(`${route}/`))
}

function isAuthPage(pathname: string): boolean {
  return AUTH_PAGES.some((route) => pathname === route || pathname.startsWith(`${route}/`))
}

export default function AuthGate({ children }: PropsWithChildren) {
  const pathname = usePathname()
  const router = useRouter()
  const [isReady, setIsReady] = useState(false)

  const routeIsPublic = useMemo(() => isPublicRoute(pathname || '/'), [pathname])
  const routeIsAuthPage = useMemo(() => isAuthPage(pathname || '/'), [pathname])
  const apiBase = getApiBaseUrl()

  useEffect(() => {
    let cancelled = false

    const run = async () => {
      const token = getAuthToken()

      if (routeIsPublic) {
        if (token) {
          const valid = await validateAuthSession(apiBase)
          if (cancelled) return

          if (valid && routeIsAuthPage) {
            router.replace('/analyze')
            setIsReady(false)
            return
          }
        }

        setIsReady(true)
        return
      }

      if (!token) {
        const nextTarget = pathname ? encodeURIComponent(pathname) : encodeURIComponent('/analyze')
        router.replace(`/login?next=${nextTarget}`)
        setIsReady(false)
        return
      }

      const valid = await validateAuthSession(apiBase)
      if (cancelled) return

      if (!valid) {
        const nextTarget = pathname ? encodeURIComponent(pathname) : encodeURIComponent('/analyze')
        router.replace(`/login?next=${nextTarget}`)
        setIsReady(false)
        return
      }

      setIsReady(true)
    }

    run()

    return () => {
      cancelled = true
    }
  }, [apiBase, pathname, routeIsAuthPage, routeIsPublic, router])

  if (!isReady) {
    return <div className="min-h-screen bg-background" />
  }

  return <>{children}</>
}
