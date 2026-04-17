export const AUTH_TOKEN_KEY = 'gitguard_token'
export const AUTH_USER_KEY = 'gitguard_user'
export const AUTH_COOKIE_NAME = 'gitguard_token'

type AuthUser = {
  id: string
  username: string
  email: string
}

type AuthPayload = {
  token: string
  id: string
  username: string
  email: string
}

function getCookieValue(name: string): string | null {
  if (typeof document === 'undefined') return null

  const encodedPrefix = `${encodeURIComponent(name)}=`
  const parts = document.cookie.split(';')

  for (const part of parts) {
    const trimmed = part.trim()
    if (trimmed.startsWith(encodedPrefix)) {
      return decodeURIComponent(trimmed.slice(encodedPrefix.length))
    }
  }

  return null
}

export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(AUTH_TOKEN_KEY) || getCookieValue(AUTH_COOKIE_NAME)
}

export function setAuthSession(data: AuthPayload): void {
  if (typeof window === 'undefined') return

  const user: AuthUser = {
    id: data.id,
    username: data.username,
    email: data.email,
  }

  localStorage.setItem(AUTH_TOKEN_KEY, data.token)
  localStorage.setItem(AUTH_USER_KEY, JSON.stringify(user))
  document.cookie = `${encodeURIComponent(AUTH_COOKIE_NAME)}=${encodeURIComponent(data.token)}; Path=/; Max-Age=2592000; SameSite=Lax`
}

export function clearAuthSession(): void {
  if (typeof window === 'undefined') return

  localStorage.removeItem(AUTH_TOKEN_KEY)
  localStorage.removeItem(AUTH_USER_KEY)
  document.cookie = `${encodeURIComponent(AUTH_COOKIE_NAME)}=; Path=/; Max-Age=0; SameSite=Lax`
}
