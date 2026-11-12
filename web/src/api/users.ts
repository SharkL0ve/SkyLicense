import request from './index'
import type { WebUser, CreateUserRequest, UpdateUserRequest, OperationLog, AdminMfaResetRequest } from '@/types'
import type { PageResult, PaginationParams } from '@/types'

export function getUsers(params: PaginationParams): Promise<PageResult<WebUser>> {
  return request.get('/users', { params })
}

export function getUser(id: number): Promise<WebUser> {
  return request.get(`/users/${id}`)
}

export function createUser(data: CreateUserRequest): Promise<WebUser> {
  return request.post('/users', data)
}

export function updateUser(id: number, data: UpdateUserRequest): Promise<WebUser> {
  return request.put(`/users/${id}`, data)
}

export function deleteUser(id: number): Promise<void> {
  return request.delete(`/users/${id}`)
}

export function toggleUserStatus(id: number, status: number): Promise<void> {
  return request.put(`/users/${id}/status`, null, { params: { status } })
}

export function resetUserMfa(id: number, data: AdminMfaResetRequest): Promise<void> {
  return request.delete(`/users/${id}/mfa`, { data })
}

export function getUserOperations(
  id: number,
  params: PaginationParams
): Promise<PageResult<OperationLog>> {
  return request.get(`/users/${id}/operations`, { params })
}
