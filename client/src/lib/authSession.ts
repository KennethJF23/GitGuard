export const AUTH_TOKEN_KEY = 'gitguard_token'
export const AUTH_USER_KEY = 'gitguard_user'
// TODO(security): migrate auth token storage to server-issued HttpOnly cookies.

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

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.')
    if (parts.length < 2) return null
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
    const decoded = atob(padded)
    return JSON.parse(decoded) as Record<string, unknown>
  } catch {
    return null
  }
}

function isTokenExpired(token: string): boolean {
  const payload = decodeJwtPayload(token)
  const exp = payload?.exp
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return false
  return Date.now() >= exp * 1000
}

export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null
  const token = localStorage.getItem(AUTH_TOKEN_KEY)
  if (!token) return null

  if (isTokenExpired(token)) {
    clearAuthSession()
    return null
  }

  return token
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
}

export function clearAuthSession(): void {
  if (typeof window === 'undefined') return

  localStorage.removeItem(AUTH_TOKEN_KEY)
  localStorage.removeItem(AUTH_USER_KEY)
}

export async function validateAuthSession(apiBase: string): Promise<boolean> {
  const token = getAuthToken()
  if (!token) return false

  try {
    const response = await fetch(`${apiBase}/api/auth/me`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })

    if (!response.ok) {
      clearAuthSession()
      return false
    }

    return true
  } catch {
    return false
  }
}
