"use client"

import { type MouseEvent, useEffect, useState, useSyncExternalStore } from 'react'
import Link from 'next/link'
import Image from 'next/image'
import { usePathname, useRouter } from 'next/navigation'
import { AnimatePresence, motion } from 'framer-motion'
import { Menu, X } from 'lucide-react'

type HeaderProps = {
  onLogin?: () => void
  onRegister?: () => void
}

type NavItem = {
  label: string
  href: string
  activeOn: string[]
}

type GuestNavItem = {
  label: string
  href: string
  sectionId: string
}

const guestNavItems: GuestNavItem[] = [
  { label: 'Home', href: '/#home', sectionId: 'home' },
  { label: 'Stats', href: '/#stats', sectionId: 'stats' },
  { label: 'Features', href: '/#features', sectionId: 'features' },
  { label: 'How it Works', href: '/#how-it-works', sectionId: 'how-it-works' },
]

export default function Header({ onLogin, onRegister }: HeaderProps) {
  const router = useRouter()
  const pathname = usePathname()
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [activeGuestSection, setActiveGuestSection] = useState('home')

  const authedNavItems: NavItem[] = [
    { label: 'Home', href: '/', activeOn: ['/'] },
    { label: 'Human Analyzer', href: '/analyze', activeOn: ['/analyze'] },
    { label: 'AI Analyzer', href: '/ai-analyze', activeOn: ['/ai-analyze', '/ai-analysis'] },
    { label: 'Malware Detector', href: '/malware-detection', activeOn: ['/malware-detection', '/malware'] },
  ]

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

  const isAuthed = Boolean(token)

  const isRouteActive = (paths: string[]) => {
    return paths.some((basePath) => pathname === basePath || pathname.startsWith(`${basePath}/`))
  }

  useEffect(() => {
    setIsMobileMenuOpen(false)
  }, [pathname])

  useEffect(() => {
    if (typeof window === 'undefined' || isAuthed || pathname !== '/') {
      return
    }

    const ids = guestNavItems.map((item) => item.sectionId)

    const updateActiveSection = () => {
      const offsetPosition = window.scrollY + 130
      let current = ids[0]

      ids.forEach((id) => {
        const section = document.getElementById(id)
        if (section && offsetPosition >= section.offsetTop) {
          current = id
        }
      })

      setActiveGuestSection(current)
    }

    updateActiveSection()
    window.addEventListener('scroll', updateActiveSection, { passive: true })
    window.addEventListener('resize', updateActiveSection)

    return () => {
      window.removeEventListener('scroll', updateActiveSection)
      window.removeEventListener('resize', updateActiveSection)
    }
  }, [isAuthed, pathname])

  useEffect(() => {
    if (typeof window === 'undefined' || isAuthed || pathname !== '/') {
      return
    }

    const pendingSection = window.sessionStorage.getItem('gitguard_pending_section')
    const hashSection = window.location.hash.replace('#', '')
    const targetSection = pendingSection || hashSection

    if (!targetSection) {
      return
    }

    window.sessionStorage.removeItem('gitguard_pending_section')

    const timer = window.setTimeout(() => {
      scrollToSection(targetSection)
    }, 90)

    return () => {
      window.clearTimeout(timer)
    }
  }, [isAuthed, pathname])

  const navLinkClass = (isActive: boolean) =>
    `inline-flex items-center rounded-full px-4 py-2 text-sm font-semibold tracking-wide transition-all duration-200 ${
      isActive
        ? 'bg-linear-to-r from-[#1f6feb]/90 to-[#58a6ff]/70 text-white shadow-[0_6px_24px_rgba(31,111,235,0.35)]'
        : 'text-[#c9d1d9] hover:text-white hover:bg-white/10'
    }`

  const handleSignOut = () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('gitguard_token')
      localStorage.removeItem('gitguard_user')
    }
    setIsMobileMenuOpen(false)
    router.push('/')
  }

  const closeMobileMenu = () => setIsMobileMenuOpen(false)

  const scrollToSection = (sectionId: string, updateHash = true) => {
    if (typeof window === 'undefined') {
      return
    }

    const section = document.getElementById(sectionId)
    if (!section) {
      return
    }

    section.scrollIntoView({ behavior: 'smooth', block: 'start' })
    setActiveGuestSection(sectionId)

    if (updateHash) {
      window.history.replaceState(null, '', `/#${sectionId}`)
    }
  }

  const handleGuestNavClick = (event: MouseEvent<HTMLAnchorElement>, sectionId: string) => {
    closeMobileMenu()

    if (pathname === '/') {
      event.preventDefault()
      scrollToSection(sectionId)
      return
    }

    event.preventDefault()
    if (typeof window !== 'undefined') {
      window.sessionStorage.setItem('gitguard_pending_section', sectionId)
    }
    router.push('/')
  }

  const openLogin = () => {
    if (onLogin) {
      onLogin()
      return
    }
    router.push('/login')
  }

  const openRegister = () => {
    if (onRegister) {
      onRegister()
      return
    }
    router.push('/signup')
  }

  const mobileMenuTransition = { duration: 0.24, ease: [0.22, 1, 0.36, 1] as const }

  return (
    <motion.header
      initial={false}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
      className="sticky top-0 z-50 w-full border-b border-white/10 bg-[#0b1220]/88 backdrop-blur-xl"
    >
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-linear-to-r from-transparent via-[#58a6ff]/70 to-transparent" />

      <div className="container mx-auto px-4 sm:px-6 lg:px-10">
        <div className="flex h-18 items-center justify-between gap-4">
          <Link
            href="/"
            aria-label="GitGuard home"
            className="group inline-flex items-center gap-3 rounded-xl border border-white/10 bg-white/5 px-2.5 py-2 transition-all hover:border-[#58a6ff]/45 hover:bg-white/10"
          >
            <span className="relative inline-flex h-10 w-10 items-center justify-center rounded-lg border border-[#58a6ff]/30 bg-[#101d34] shadow-[0_0_0_1px_rgba(88,166,255,0.2),0_6px_18px_rgba(13,24,45,0.45)]">
              <Image
                src="/logomailinblack2.webp"
                alt="GitGuard Logo"
                width={30}
                height={30}
                className="h-7 w-7 object-contain"
              />
            </span>
            <span className="flex items-center gap-2">
              <span className="rs-text-glow text-lg font-bold tracking-tight text-white">GitGuard</span>
              <span className="hidden rounded-full border border-white/20 bg-white/5 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-[#9fb5d4] sm:inline-flex">
                Security Suite
              </span>
            </span>
          </Link>

          <nav className="hidden md:flex items-center rounded-full border border-white/10 bg-white/4 p-1.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
            {isAuthed ? (
              <>
                {authedNavItems.map((item) => {
                  const active = isRouteActive(item.activeOn)
                  return (
                    <Link
                      key={item.label}
                      href={item.href}
                      className={navLinkClass(active)}
                      aria-current={active ? 'page' : undefined}
                    >
                      {item.label}
                    </Link>
                  )
                })}
              </>
            ) : (
              <>
                {guestNavItems.map((item) => (
                  <Link
                    key={item.sectionId}
                    href={item.href}
                    onClick={(event) => handleGuestNavClick(event, item.sectionId)}
                    className={navLinkClass(pathname === '/' && activeGuestSection === item.sectionId)}
                    aria-current={pathname === '/' && activeGuestSection === item.sectionId ? 'page' : undefined}
                  >
                    {item.label}
                  </Link>
                ))}
              </>
            )}
          </nav>

          <div className="flex items-center gap-2 sm:gap-3">
            {isAuthed ? (
              <button
                type="button"
                onClick={handleSignOut}
                className="hidden md:inline-flex rounded-full border border-white/15 px-4 py-2 text-sm font-semibold text-[#c9d1d9] transition-all hover:border-[#f85149]/50 hover:bg-[#f85149]/12 hover:text-white"
              >
                Sign out
              </button>
            ) : (
              <>
                <button
                  type="button"
                  onClick={openLogin}
                  className="hidden md:inline-flex rounded-full border border-white/15 px-4 py-2 text-sm font-semibold text-[#c9d1d9] transition-all hover:border-[#58a6ff]/50 hover:bg-white/8 hover:text-white"
                >
                  Sign in
                </button>
                <button
                  type="button"
                  onClick={openRegister}
                  className="hidden md:inline-flex rounded-full bg-linear-to-r from-[#1f6feb] to-[#58a6ff] px-4 py-2 text-sm font-semibold text-white shadow-[0_10px_24px_rgba(31,111,235,0.35)] transition-all hover:brightness-110"
                >
                  Create account
                </button>
              </>
            )}

            <button
              type="button"
              onClick={() => setIsMobileMenuOpen((prev) => !prev)}
              className="md:hidden inline-flex items-center justify-center rounded-lg border border-white/15 bg-white/5 p-2 text-[#c9d1d9] transition-all hover:border-[#58a6ff]/50 hover:text-white"
              aria-label={isMobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={isMobileMenuOpen}
              aria-controls="mobile-navigation"
            >
              <AnimatePresence mode="wait" initial={false}>
                {isMobileMenuOpen ? (
                  <motion.span
                    key="menu-close"
                    initial={false}
                    animate={{ opacity: 1, rotate: 0, scale: 1 }}
                    exit={{ opacity: 0, rotate: 90, scale: 0.85 }}
                    transition={mobileMenuTransition}
                    className="inline-flex"
                  >
                    <X className="h-5 w-5" />
                  </motion.span>
                ) : (
                  <motion.span
                    key="menu-open"
                    initial={false}
                    animate={{ opacity: 1, rotate: 0, scale: 1 }}
                    exit={{ opacity: 0, rotate: -90, scale: 0.85 }}
                    transition={mobileMenuTransition}
                    className="inline-flex"
                  >
                    <Menu className="h-5 w-5" />
                  </motion.span>
                )}
              </AnimatePresence>
            </button>
          </div>
        </div>

        <AnimatePresence initial={false}>
          {isMobileMenuOpen ? (
            <motion.nav
              id="mobile-navigation"
              className="md:hidden overflow-hidden"
              initial={false}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={mobileMenuTransition}
            >
              <motion.div
                className="mb-4 rounded-2xl border border-white/10 bg-linear-to-b from-white/10 to-white/5 p-3 shadow-[0_14px_30px_rgba(0,0,0,0.32)]"
                initial={false}
                animate={{ y: 0, opacity: 1 }}
                exit={{ y: -6, opacity: 0 }}
                transition={mobileMenuTransition}
              >
                {isAuthed ? (
                  <div className="grid grid-cols-1 gap-2">
                    {authedNavItems.map((item) => {
                      const active = isRouteActive(item.activeOn)
                      return (
                        <Link
                          key={item.label}
                          href={item.href}
                          onClick={closeMobileMenu}
                          className={
                            'rounded-xl border px-3.5 py-2.5 text-sm font-semibold transition-all ' +
                            (active
                              ? 'border-[#58a6ff]/50 bg-[#1f6feb]/20 text-white'
                              : 'border-white/12 text-[#c9d1d9] hover:border-[#58a6ff]/45 hover:bg-white/8 hover:text-white')
                          }
                          aria-current={active ? 'page' : undefined}
                        >
                          {item.label}
                        </Link>
                      )
                    })}

                    <button
                      type="button"
                      onClick={handleSignOut}
                      className="rounded-xl border border-white/12 px-3.5 py-2.5 text-left text-sm font-semibold text-[#c9d1d9] transition-all hover:border-[#f85149]/55 hover:bg-[#f85149]/15 hover:text-white"
                    >
                      Sign out
                    </button>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-2">
                    {guestNavItems.map((item) => {
                      const active = pathname === '/' && activeGuestSection === item.sectionId

                      return (
                        <Link
                          key={item.sectionId}
                          href={item.href}
                          onClick={(event) => handleGuestNavClick(event, item.sectionId)}
                          className={
                            'rounded-xl border px-3.5 py-2.5 text-sm font-semibold transition-all ' +
                            (active
                              ? 'border-[#58a6ff]/50 bg-[#1f6feb]/20 text-white'
                              : 'border-white/12 text-[#c9d1d9] hover:border-[#58a6ff]/45 hover:bg-white/8 hover:text-white')
                          }
                          aria-current={active ? 'page' : undefined}
                        >
                          {item.label}
                        </Link>
                      )
                    })}
                    <button
                      type="button"
                      onClick={() => {
                        closeMobileMenu()
                        openLogin()
                      }}
                      className="rounded-xl border border-white/12 px-3.5 py-2.5 text-left text-sm font-semibold text-[#c9d1d9] transition-all hover:border-[#58a6ff]/45 hover:bg-white/8 hover:text-white"
                    >
                      Sign in
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        closeMobileMenu()
                        openRegister()
                      }}
                      className="rounded-xl bg-linear-to-r from-[#1f6feb] to-[#58a6ff] px-3.5 py-2.5 text-left text-sm font-semibold text-white shadow-[0_10px_22px_rgba(31,111,235,0.38)]"
                    >
                      Create account
                    </button>
                  </div>
                )}
              </motion.div>
            </motion.nav>
          ) : null}
        </AnimatePresence>
      </div>
    </motion.header>
  )
}
