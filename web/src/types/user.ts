export interface WebUser {
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

export interface CreateUserRequest {
  username: string
  password: string
  role?: 'USER' | 'ADMIN'
  maxPrograms?: number
}

export interface UpdateUserRequest {
  username?: string
  password?: string
  role?: 'USER' | 'ADMIN'
  maxPrograms?: number
}

export interface AdminMfaResetRequest {
  password: string
  factor?: string
}

export interface OperationLog {
  id: number
  eventId: string
  userId: number
  username: string | null
  action: string
  target: string
  detail: string | null
  ip: string | null
  timestamp: string
  outcome: 'ATTEMPT' | 'SUCCESS' | 'REJECTED' | 'LEGACY' | string
  occurredAtMillis: number
  completedAtMillis: number | null
}

export interface OperationIntegrity {
  verified: boolean
  rowCount: number
  anchorId: number
  headId: number
  checkedAtMillis: number
  status: string
}

export interface SystemStats {
  userCount: number
  programCount: number
  licenseCount: number
  activeLicenses: number
  bannedLicenses: number
  banRecordCount: number
  authLogCount: number
  versionCount: number
  activeWebSessionCount: number
  activeClientSessionCount: number
  authRateLimitTrackedAddresses: number
  authRateLimitRejectedCount: number
  authRateLimitCapacityRejectedCount: number
  heartbeatRateLimitTrackedAddresses: number
  heartbeatRateLimitRejectedCount: number
  heartbeatRateLimitCapacityRejectedCount: number
}
