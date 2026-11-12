import request from './index'
import type { BanRecord, CreateBanRequest } from '@/types'
import type { PageResult, PaginationParams } from '@/types'

export function getBans(params: PaginationParams & { type?: string }): Promise<PageResult<BanRecord>> {
  return request.get('/bans', { params })
}

export function getBansByProgram(
  programId: number,
  params: PaginationParams
): Promise<PageResult<BanRecord>> {
  return request.get(`/bans/program/${programId}`, { params })
}

export function createBan(data: CreateBanRequest): Promise<BanRecord> {
  return request.post('/bans', data)
}

export function deleteBan(id: number): Promise<void> {
  return request.delete(`/bans/${id}`)
}
