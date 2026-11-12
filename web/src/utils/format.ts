import { AUTH_RESULTS } from './constants'

export function formatTime(time: string | null | undefined): string {
  if (!time) return '-'
  return /^\d{4}-\d{2}-\d{2}-\d{2}:\d{2}$/.test(time)
    ? `${time.slice(0, 10)} ${time.slice(11)}`
    : time.replace('T', ' ')
}

export function formatStatus(status: number): string {
  return status === 1 ? '正常' : '禁用'
}

export function formatBanType(type: string): string {
  const map: Record<string, string> = {
    IP: 'IP地址',
    HWID: '机器码',
    QQ: 'QQ号',
    CODE: '许可证',
  }
  return map[type] || type
}

export function formatAuthResult(result: string): string {
  return AUTH_RESULTS.find((item) => item.value === result)?.label || result
}

export type AuthResultTone = 'success' | 'warning' | 'danger'

export function authResultTone(result: string): AuthResultTone {
  if (result === 'OK') return 'success'
  if (result === 'PENDING'
    || result === 'RELEASED'
    || result.includes('LIMIT')
    || result.includes('MISSING')
    || result === 'DAILY_AUTH_LIMIT'
    || result === 'BINDING_REVOKED'
    || result === 'EXPIRED') {
    return 'warning'
  }
  return 'danger'
}

export function splitList(str: string | null | undefined): string[] {
  if (!str) return []
  return [...new Set(str.split(',').map((value) => value.trim()).filter(Boolean))]
}
