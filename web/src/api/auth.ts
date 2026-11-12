import request from './index'
import type {
  LoginRequest,
  LoginResponse,
  SessionResponse,
  UserInfo,
  ChangePasswordRequest,
  MfaChallengeRequest,
  MfaEnrollmentStartRequest,
  MfaFactorRequest,
  MfaManageRequest,
  MfaEnrollmentResponse,
  MfaStatusResponse,
  MfaRecoveryCodesResponse,
} from '@/types'

export function login(data: LoginRequest): Promise<LoginResponse> {
  return request.post('/auth/login', data)
}

export function logout(): Promise<void> {
  return request.post('/auth/logout')
}

export function getUserInfo(): Promise<UserInfo> {
  return request.get('/auth/me')
}

export function getSession(): Promise<SessionResponse> {
  return request.get('/auth/session')
}

export function changePassword(data: ChangePasswordRequest): Promise<void> {
  return request.put('/auth/password', data)
}

export function verifyMfa(data: MfaChallengeRequest): Promise<LoginResponse> {
  return request.post('/auth/mfa/verify', data)
}

export function getMfaStatus(): Promise<MfaStatusResponse> {
  return request.get('/auth/mfa/status')
}

export function startMfaEnrollment(data: MfaEnrollmentStartRequest): Promise<MfaEnrollmentResponse> {
  return request.post('/auth/mfa/enrollment', data)
}

export function confirmMfaEnrollment(data: MfaFactorRequest): Promise<MfaRecoveryCodesResponse> {
  return request.post('/auth/mfa/enrollment/confirm', data)
}

export function regenerateMfaRecoveryCodes(data: MfaManageRequest): Promise<MfaRecoveryCodesResponse> {
  return request.post('/auth/mfa/recovery-codes', data)
}

export function disableMfa(data: MfaManageRequest): Promise<void> {
  return request.delete('/auth/mfa', { data })
}
