import request from './index'
import type {
  Program,
  ProgramVersion,
  CreateProgramRequest,
  UpdateProgramRequest,
  AuthLog,
  AuthLogQuery,
} from '@/types'
import type { PageResult, PaginationParams } from '@/types'
import type { AxiosProgressEvent } from 'axios'

export function getPrograms(params: PaginationParams): Promise<PageResult<Program>> {
  return request.get('/programs', { params })
}

export function getProgram(id: number): Promise<Program> {
  return request.get(`/programs/${id}`)
}

export function createProgram(data: CreateProgramRequest): Promise<Program> {
  return request.post('/programs', data)
}

export function updateProgram(id: number, data: UpdateProgramRequest): Promise<Program> {
  return request.put(`/programs/${id}`, data)
}

export function deleteProgram(id: number): Promise<void> {
  return request.delete(`/programs/${id}`)
}

export function toggleProgramStatus(id: number, status: number): Promise<void> {
  return request.put(`/programs/${id}/status`, null, { params: { status } })
}

export function getProgramVersions(id: number): Promise<ProgramVersion[]> {
  return request.get(`/programs/${id}/versions`)
}

export function getProgramAuthLogs(
  id: number,
  params: PaginationParams & AuthLogQuery
): Promise<PageResult<AuthLog>> {
  return request.get(`/programs/${id}/auth-logs`, { params })
}

export function uploadVersion(
  id: number,
  version: string,
  file: File,
  onProgress?: (percent: number) => void
): Promise<ProgramVersion> {
  const formData = new FormData()
  formData.append('file', file)
  return request.post(`/programs/${id}/versions`, formData, {
    params: { version },
    timeout: 300000,
    onUploadProgress: (event: AxiosProgressEvent) => {
      if (!event.total || !onProgress) return
      onProgress(Math.min(100, Math.round((event.loaded / event.total) * 100)))
    },
  })
}

export function deleteVersion(programId: number, versionId: number): Promise<void> {
  return request.delete(`/programs/${programId}/versions/${versionId}`)
}
