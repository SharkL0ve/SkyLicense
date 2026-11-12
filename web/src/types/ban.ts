export type BanType = 'IP' | 'HWID' | 'QQ' | 'CODE'

export interface BanRecord {
  id: number
  type: BanType
  value: string
  reason: string
  operatorId: number
  programId: number | null
  createTime: string
  expirationDate: string | null
  status: number
}

export interface CreateBanRequest {
  type: BanType
  value: string
  reason?: string
  programId?: number
  expirationDate?: string
}
