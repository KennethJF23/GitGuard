'use client'

import { useEffect, useMemo, useState, type PropsWithChildren } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { getAuthToken } from '@/lib/authSession'

const PUBLIC_ROUTES = ['/login', '/signup']

function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some((route) => pathname === route || pathname.startsWith(`${route}/`))
}

export default function AuthGate({ children }: PropsWithChildren) {
  const pathname = usePathname()
  const router = useRouter()
  const [isReady, setIsReady] = useState(false)

  const routeIsPublic = useMemo(() => isPublicRoute(pathname || '/'), [pathname])

  useEffect(() => {
    const token = getAuthToken()

    if (routeIsPublic) {
      if (token) {
        router.replace('/analyze')
        setIsReady(false)
        return
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

    setIsReady(true)
  }, [pathname, routeIsPublic, router])

  if (!isReady) {
    return <div className="min-h-screen bg-background" />
  }

  return <>{children}</>
}
