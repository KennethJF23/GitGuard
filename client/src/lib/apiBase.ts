function stripTrailingSlashes(url: string): string {
  return String(url || "").trim().replace(/\/+$/, "")
}

function isLoopbackHost(value: string): boolean {
  const host = String(value || "").trim().toLowerCase()
  return host === "localhost" || host === "127.0.0.1" || host === "::1"
}

const DEFAULT_DEPLOYED_API_BASE_URL = 'https://gitguard.onrender.com'

export function getApiBaseUrl(): string {
  const envBase = stripTrailingSlashes(
    process.env.NEXT_PUBLIC_API_BASE_URL || process.env.NEXT_PUBLIC_API_URL || '',
  )

  if (typeof window === 'undefined') {
    return envBase || DEFAULT_DEPLOYED_API_BASE_URL
  }

  const currentHost = window.location.hostname

  // If frontend is opened from LAN IP, never force localhost backend.
  if (envBase) {
    try {
      const envUrl = new URL(envBase)
      if (!isLoopbackHost(currentHost) && isLoopbackHost(envUrl.hostname)) {
        return `${envUrl.protocol}//${currentHost}${envUrl.port ? `:${envUrl.port}` : ''}`
      }
      return envBase
    } catch {
      // If malformed env URL, fall through to safe default.
    }
  }

  if (isLoopbackHost(currentHost)) {
    return `http://${currentHost}:5000`
  }

  return DEFAULT_DEPLOYED_API_BASE_URL
}
