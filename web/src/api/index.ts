import axios, { AxiosError } from 'axios'
import { ElMessage } from 'element-plus'
import type { ApiResponse } from '@/types'
import {
  clearSessionState,
  getCsrfToken,
  removeLegacyBearerToken,
} from '@/utils/session'

export const AUTH_EXPIRED_EVENT = 'skylicense:auth-expired'
const CSRF_HEADER = 'X-CSRF-Token'
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

removeLegacyBearerToken()

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly code?: number,
    public readonly status?: number,
    public readonly cause?: unknown
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

const request = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000,
  withCredentials: true,
})

let authExpiredNotified = false

function isLoginFlowRequest(url: string | undefined): boolean {
  return url === '/auth/login' || url === '/auth/mfa/verify'
}

function readErrorEnvelope(value: unknown): { code?: number; message?: string } {
  if (!value || typeof value !== 'object') return {}
  const candidate = value as Record<string, unknown>
  return {
    code: typeof candidate.code === 'number' ? candidate.code : undefined,
    message: typeof candidate.message === 'string' ? candidate.message : undefined,
  }
}

function expireSession(message = '登录状态已失效，请重新登录'): void {
  clearSessionState()
  if (authExpiredNotified) return
  authExpiredNotified = true
  ElMessage.warning(message)
  window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT))
  window.setTimeout(() => {
    authExpiredNotified = false
  }, 500)
}

function showHttpError(status: number | undefined, message: string): void {
  if (status === 403) {
    ElMessage.error(message || '没有权限执行此操作')
    return
  }
  if (status && status >= 500) {
    ElMessage.error(message || '服务暂时不可用，请稍后重试')
    return
  }
  ElMessage.error(message)
}

request.interceptors.request.use((config) => {
  const method = (config.method || 'GET').toUpperCase()
  const csrfToken = getCsrfToken()
  if (!SAFE_METHODS.has(method) && csrfToken) {
    config.headers[CSRF_HEADER] = csrfToken
  }
  return config
})

request.interceptors.response.use(
  (response) => {
    const payload = response.data as ApiResponse<unknown>
    if (!payload || typeof payload.code !== 'number' || !('data' in payload)) {
      const message = '服务器返回了无法识别的数据格式'
      ElMessage.error(message)
      return Promise.reject(new ApiError(message, undefined, response.status))
    }

    if (payload.code < 200 || payload.code >= 300) {
      const message = payload.message || '请求失败'
      if (payload.code === 401) {
        if (isLoginFlowRequest(response.config.url)) showHttpError(401, message)
        else expireSession()
      } else {
        showHttpError(payload.code, message)
      }
      return Promise.reject(new ApiError(message, payload.code, response.status))
    }

    // Axios 的拦截器类型固定要求 AxiosResponse；运行时在此统一解包业务 data。
    return payload.data as never
  },
  (error: AxiosError<unknown>) => {
    if (axios.isCancel(error)) {
      return Promise.reject(error)
    }

    const status = error.response?.status
    const envelope = readErrorEnvelope(error.response?.data)
    const code = envelope.code ?? status
    let message = envelope.message || error.message || '网络请求失败'

    if (error.code === 'ECONNABORTED') {
      message = '请求超时，请检查网络后重试'
    } else if (!error.response) {
      message = navigator.onLine ? '无法连接服务器，请稍后重试' : '网络已断开，请检查连接'
    }

    if (code === 401) {
      if (isLoginFlowRequest(error.config?.url)) showHttpError(401, message)
      else expireSession()
    } else {
      showHttpError(status, message)
    }
    return Promise.reject(new ApiError(message, code, status, error))
  }
)

export default request
