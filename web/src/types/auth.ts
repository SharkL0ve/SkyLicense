export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  csrfToken: string | null
  expiresInSeconds: number
  mfaRequired: boolean
  challengeToken: string | null
}

export interface SessionResponse {
  user: UserInfo
  csrfToken: string
}

export interface ChangePasswordRequest {
  oldPassword: string
  newPassword: string
}

export interface MfaChallengeRequest {
  challengeToken: string
  factor: string
}

export interface MfaEnrollmentStartRequest {
  password: string
}

export interface MfaFactorRequest {
  factor: string
}

export interface MfaManageRequest {
  password: string
  factor: string
}

export interface MfaEnrollmentResponse {
  manualSecret: string
  otpauthUri: string
  expiresInSeconds: number
}

export interface MfaStatusResponse {
  enabled: boolean
  remainingRecoveryCodes: number
}

export interface MfaRecoveryCodesResponse {
  recoveryCodes: string[]
}

export interface UserInfo {
  id: number
  username: string
  role: 'USER' | 'ADMIN'
  maxPrograms: number
  status: number
  createTime: string
  lastLoginTime: string | null
  email: string | null
  mfaEnabled: number
  mfaUpdatedAt: number | null
}
