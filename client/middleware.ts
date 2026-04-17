import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const AUTH_PAGES = ['/login', '/signup']
const PUBLIC_ROUTES = ['/', ...AUTH_PAGES]

function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some((route) => pathname === route || pathname.startsWith(`${route}/`))
}

function isAuthPage(pathname: string): boolean {
  return AUTH_PAGES.some((route) => pathname === route || pathname.startsWith(`${route}/`))
}

export function middleware(request: NextRequest) {
  const { pathname, search } = request.nextUrl

  if (pathname.startsWith('/_next') || pathname.startsWith('/api') || pathname === '/favicon.ico') {
    return NextResponse.next()
  }

  const token = request.cookies.get('gitguard_token')?.value
  const publicRoute = isPublicRoute(pathname)
  const authPage = isAuthPage(pathname)

  if (!token && !publicRoute) {
    const loginUrl = new URL('/login', request.url)
    loginUrl.searchParams.set('next', `${pathname}${search}`)
    return NextResponse.redirect(loginUrl)
  }

  if (token && authPage) {
    return NextResponse.redirect(new URL('/analyze', request.url))
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
