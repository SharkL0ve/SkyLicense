const LEGACY_TOKEN_KEY = 'skylicense_token'

let csrfToken: string | null = null

export function getCsrfToken(): string | null {
  return csrfToken
}

export function setCsrfToken(value: string): void {
  csrfToken = value
}

export function clearSessionState(): void {
  csrfToken = null
}

export function removeLegacyBearerToken(): void {
  try {
    localStorage.removeItem(LEGACY_TOKEN_KEY)
  } catch {
    // Storage may be unavailable under hardened browser privacy settings.
  }
}
