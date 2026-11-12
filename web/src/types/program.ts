export interface Program {
  id: number
  userId: number
  name: string
  description: string | null
  status: number
  createTime: string
}

export interface ProgramVersion {
  id: number
  programId: number
  version: string
  fileName: string
  filePath: string
  entryClass: string | null
  entryPoint: string | null
  uploadTime: string
  releaseNotes: string | null
}

export interface CreateProgramRequest {
  name: string
  description?: string
}

export interface UpdateProgramRequest {
  name?: string
  description?: string
}
