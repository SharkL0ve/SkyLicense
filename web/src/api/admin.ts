import request from './index'
import type {
  Program,
  License,
  OperationLog,
  SystemStats,
  AuthLog,
  AuthLogQuery,
  AdminCreateLicenseRequest,
  OperationIntegrity,
} from '@/types'
import type { PageResult, PaginationParams } from '@/types'

export function getAdminPrograms(params: PaginationParams): Promise<PageResult<Program>> {
  return request.get('/admin/programs', { params })
}

export function getAdminLicenses(params: PaginationParams): Promise<PageResult<License>> {
  return request.get('/admin/licenses', { params })
}

export function adminCreateLicense(
  data: AdminCreateLicenseRequest
): Promise<License[]> {
  return request.post('/admin/licenses', data)
}

export function getAdminOperations(params: PaginationParams): Promise<PageResult<OperationLog>> {
  return request.get('/admin/operations', { params })
}

export function getAdminOperationIntegrity(): Promise<OperationIntegrity> {
  return request.get('/admin/operations/integrity')
}

export function reloadResources(): Promise<void> {
  return request.post('/admin/reload')
}

export function getSystemStats(): Promise<SystemStats> {
  return request.get('/admin/stats')
}

export function getAdminAuthLogs(
  params: PaginationParams & AuthLogQuery
): Promise<PageResult<AuthLog>> {
  return request.get('/admin/auth-logs', { params })
}
