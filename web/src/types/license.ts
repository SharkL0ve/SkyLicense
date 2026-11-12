export interface License {
  id: number
  code: string
  programId: number
  userId: number
  qq: string | null
  bindableIps: number
  bindableHwids: number
  status: number
  ips: string | null
  hwids: string | null
  createTime: string
  lastAuthTime: string | null
  banReason: string | null
  notes: string | null
  expirationDate: string | null
  maxDailyAuth: number
  lastModifiedTime: string | null
}

export interface CreateLicenseRequest {
  code?: string
  qq?: string
  bindableIps?: number
  bindableHwids?: number
  notes?: string
  expirationDate?: string
  maxDailyAuth?: number
}

export interface UpdateLicenseRequest {
  qq?: string
  bindableIps?: number
  bindableHwids?: number
  notes?: string
  expirationDate?: string
  maxDailyAuth?: number
}

export interface MultiCreateLicenseRequest extends CreateLicenseRequest {
  programIds: number[]
}

export interface AdminCreateLicenseRequest extends CreateLicenseRequest {
  programIds: number[]
  allPrograms?: boolean
}

export interface UnbindRequest {
  ip?: string
  hwid?: string
  all?: boolean
}

export interface BatchLicenseRequest {
  codes: string[]
  reason?: string
}

export interface LicenseFilter {
  status?: string
  qq?: string
  ip?: string
  hwid?: string
  keyword?: string
  sortBy?: string
  order?: 'asc' | 'desc'
}

export interface AuthLog {
  id: number
  licenseId: number
  code: string
  ip: string
  hwid: string
  result: string
  timestamp: string
  programId: number
  userId: number
}

export type AuthResult =
  | 'OK'
  | 'PENDING'
  | 'RELEASED'
  | 'FAILED'
  | 'BANNED'
  | 'BANNED_BY_IP'
  | 'BANNED_BY_QQ'
  | 'BANNED_BY_HWID'
  | 'BANNED_BY_CODE'
  | 'PROGRAM_DISABLED'
  | 'PROGRAM_MISMATCH'
  | 'LICENSE_OWNER_MISMATCH'
  | 'USER_DISABLED'
  | 'IP_LIMIT'
  | 'HWID_LIMIT'
  | 'IP_MISSING'
  | 'HWID_MISSING'
  | 'BINDING_REVOKED'
  | 'EXPIRED'
  | 'DAILY_AUTH_LIMIT'
  | 'DELIVERY_FAILED'
  | 'DELIVERY_UNCONFIRMED'

export interface AuthLogQuery {
  programId?: number
  code?: string
  ip?: string
  hwid?: string
  result?: string
  startTime?: string
  endTime?: string
}
