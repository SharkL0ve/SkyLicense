import request from './index'
import type {
  License,
  CreateLicenseRequest,
  UpdateLicenseRequest,
  UnbindRequest,
  BatchLicenseRequest,
  LicenseFilter,
  AuthLog,
  AuthLogQuery,
  MultiCreateLicenseRequest,
} from '@/types'
import type { PageResult, PaginationParams } from '@/types'

function licensePath(code: string): string {
  return `/licenses/${encodeURIComponent(code)}`
}

export function getLicenses(
  programId: number,
  params: PaginationParams & LicenseFilter
): Promise<PageResult<License>> {
  return request.get(`/programs/${programId}/licenses`, { params })
}

export function createLicense(programId: number, data: CreateLicenseRequest): Promise<License> {
  return request.post(`/programs/${programId}/licenses`, data)
}

export function getLicenseDetail(code: string): Promise<License> {
  return request.get(licensePath(code))
}

export function updateLicense(code: string, data: UpdateLicenseRequest): Promise<License> {
  return request.put(licensePath(code), data)
}

export function deleteLicense(code: string): Promise<void> {
  return request.delete(licensePath(code))
}

export function unbindLicense(code: string, data: UnbindRequest): Promise<License> {
  return request.put(`${licensePath(code)}/unbind`, data)
}

export function banLicense(code: string, reason?: string): Promise<void> {
  return request.put(`${licensePath(code)}/ban`, null, { params: { reason } })
}

export function unbanLicense(code: string): Promise<void> {
  return request.put(`${licensePath(code)}/unban`)
}

export function getLicenseLogs(
  code: string,
  params: PaginationParams
): Promise<PageResult<AuthLog>> {
  return request.get(`${licensePath(code)}/logs`, { params })
}

export function batchBan(data: BatchLicenseRequest): Promise<{ affected: number }> {
  return request.put('/licenses/batch/ban', data)
}

export function batchUnban(data: BatchLicenseRequest): Promise<{ affected: number }> {
  return request.put('/licenses/batch/unban', data)
}

export function batchDelete(data: BatchLicenseRequest): Promise<{ affected: number }> {
  return request.delete('/licenses/batch', { data })
}

export function getAuthLogs(
  params: PaginationParams & AuthLogQuery
): Promise<PageResult<AuthLog>> {
  return request.get('/auth-logs', { params })
}

export function createLicenseMulti(data: MultiCreateLicenseRequest): Promise<License[]> {
  return request.post('/licenses/multi', data)
}
