import type { FormItemRule } from 'element-plus'

export const PASSWORD_MIN_LENGTH = 12
export const PASSWORD_MAX_LENGTH = 128
export const PASSWORD_HINT = '12–128 位，且至少包含大写字母、小写字母、数字、符号中的三类'
export const USERNAME_HINT = '3–64 位，只能包含字母、数字、点、下划线和连字符'

export function isStrongPassword(password: string): boolean {
  if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
    return false
  }

  const classes = [
    /\p{Ll}/u.test(password),
    /\p{Lu}/u.test(password),
    /\p{N}/u.test(password),
    /[^\p{L}\p{N}]/u.test(password),
  ]
  return classes.filter(Boolean).length >= 3
}

export function passwordRule(options: { required?: boolean } = {}): FormItemRule {
  return {
    trigger: 'blur',
    validator: (_rule, value: unknown, callback) => {
      const password = typeof value === 'string' ? value : ''
      if (!password && !options.required) {
        callback()
        return
      }
      if (!password) {
        callback(new Error('请输入密码'))
        return
      }
      if (!isStrongPassword(password)) {
        callback(new Error(PASSWORD_HINT))
        return
      }
      callback()
    },
  }
}

export const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$/
export const USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._\-]{2,63}$/
export const PROGRAM_NAME_PATTERN = VERSION_PATTERN
export const LICENSE_CODE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+\-]{0,255}$/
export const QQ_PATTERN = /^[0-9]{1,20}$/
export const HWID_PATTERN = /^[A-Za-z0-9+/]{43}=$/
export const MAX_JAR_SIZE = 64 * 1024 * 1024

export function usernameRule(): FormItemRule {
  return {
    trigger: 'blur',
    validator: (_rule, value: unknown, callback) => {
      const username = typeof value === 'string' ? value.trim() : ''
      if (!username) {
        callback(new Error('请输入用户名'))
      } else if (!USERNAME_PATTERN.test(username)) {
        callback(new Error(USERNAME_HINT))
      } else {
        callback()
      }
    },
  }
}

export function isValidLicenseCode(value: string): boolean {
  return LICENSE_CODE_PATTERN.test(value.trim())
}

export function isValidQq(value: string): boolean {
  return QQ_PATTERN.test(value.trim())
}

export function isValidHwid(value: string): boolean {
  const normalized = value.trim()
  if (!HWID_PATTERN.test(normalized) || typeof atob !== 'function') return false
  try {
    const decoded = atob(normalized)
    if (decoded.length !== 32) return false
    let nonZero = false
    for (let index = 0; index < decoded.length; index += 1) {
      nonZero ||= decoded.charCodeAt(index) !== 0
    }
    return nonZero
  } catch {
    return false
  }
}

function isValidIpv4(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => {
    if (!/^[0-9]{1,3}$/.test(part)) return false
    if (part.length > 1 && part.startsWith('0')) return false
    const number = Number(part)
    return number >= 0 && number <= 255
  })
}

/** Mirrors the server's numeric IPv4/IPv6 literal boundary; zone IDs are rejected. */
export function isValidIpLiteral(value: string): boolean {
  const normalized = value.trim()
  if (!normalized || normalized.includes('%')) return false
  if (isValidIpv4(normalized)) return true

  let candidate = normalized
  if (candidate.includes('.')) {
    const separator = candidate.lastIndexOf(':')
    if (separator < 0 || !isValidIpv4(candidate.slice(separator + 1))) return false
    candidate = `${candidate.slice(0, separator)}:0:0`
  }

  const compressionCount = (candidate.match(/::/g) || []).length
  if (compressionCount > 1) return false
  const hasCompression = compressionCount === 1
  if (hasCompression && candidate.replace('::', '').includes('::')) return false
  const sections = hasCompression ? candidate.split('::') : [candidate]
  const left = sections[0] ? sections[0].split(':') : []
  const right = sections.length === 2 && sections[1] ? sections[1].split(':') : []
  const validSection = (section: string) => /^[0-9A-Fa-f]{1,4}$/.test(section)
  if (!left.every(validSection) || !right.every(validSection)) return false
  const count = left.length + right.length
  return hasCompression ? count < 8 : count === 8
}

export type BanValueType = 'IP' | 'HWID' | 'QQ' | 'CODE'

export function isValidBanValue(type: BanValueType, value: string): boolean {
  switch (type) {
    case 'IP':
      return isValidIpLiteral(value)
    case 'HWID':
      return isValidHwid(value)
    case 'QQ':
      return isValidQq(value)
    case 'CODE':
      return isValidLicenseCode(value)
  }
}
