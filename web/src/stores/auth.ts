import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { login as loginApi, logout as logoutApi, getSession, verifyMfa as verifyMfaApi } from '@/api/auth'
import { clearSessionState, setCsrfToken } from '@/utils/session'
import type { UserInfo, LoginRequest } from '@/types'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<UserInfo | null>(null)

  const isAdmin = computed(() => user.value?.role === 'ADMIN')
  const adminMfaRequired = computed(
    () => isAdmin.value && user.value?.mfaEnabled !== 1
  )
  const isLoggedIn = computed(() => !!user.value)

  async function login(credentials: LoginRequest) {
    const data = await loginApi(credentials)
    if (data.mfaRequired) {
      clearSessionState()
      return data
    }
    if (!data.csrfToken) {
      throw new Error('服务器未返回会话凭据')
    }
    setCsrfToken(data.csrfToken)
    try {
      await fetchUserInfo()
    } catch (error) {
      reset()
      throw error
    }
    return data
  }

  async function verifyMfa(challengeToken: string, factor: string) {
    const data = await verifyMfaApi({ challengeToken, factor })
    if (data.mfaRequired || !data.csrfToken) {
      throw new Error('MFA 验证未建立会话')
    }
    setCsrfToken(data.csrfToken)
    try {
      await fetchUserInfo()
    } catch (error) {
      reset()
      throw error
    }
  }

  async function fetchUserInfo() {
    const session = await getSession()
    setCsrfToken(session.csrfToken)
    user.value = session.user
  }

  async function logout() {
    try {
      await logoutApi()
    } finally {
      user.value = null
      clearSessionState()
    }
  }

  function reset() {
    user.value = null
    clearSessionState()
  }

  return {
    user,
    isAdmin,
    adminMfaRequired,
    isLoggedIn,
    login,
    verifyMfa,
    fetchUserInfo,
    logout,
    reset,
  }
})
