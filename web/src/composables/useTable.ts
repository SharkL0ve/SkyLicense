import { ref, reactive } from 'vue'
import type { PaginationParams } from '@/types'

export function useTable<T, F extends Record<string, unknown> = Record<string, unknown>>(
  fetchFn: (params: PaginationParams & F) => Promise<{ records: T[]; total: number }>
) {
  const tableData = ref<T[]>([])
  const total = ref(0)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const pagination = reactive({ page: 1, pageSize: 20 })
  let latestRequest = 0

  async function load(filters?: F): Promise<void> {
    const requestId = ++latestRequest
    loading.value = true
    error.value = null
    try {
      const result = await fetchFn({ ...pagination, ...filters } as PaginationParams & F)
      if (requestId !== latestRequest) return
      tableData.value = result.records
      total.value = result.total
      const lastPage = Math.max(1, Math.ceil(result.total / pagination.pageSize))
      if (pagination.page > lastPage) {
        pagination.page = lastPage
        await load(filters)
      }
    } catch (cause) {
      if (requestId === latestRequest) {
        error.value = cause instanceof Error ? cause.message : '数据加载失败'
      }
    } finally {
      if (requestId === latestRequest) loading.value = false
    }
  }

  function onPageChange(page: number, filters?: F): Promise<void> {
    pagination.page = page
    return load(filters)
  }

  function onSizeChange(size: number, filters?: F): Promise<void> {
    pagination.pageSize = Math.min(200, Math.max(1, size))
    pagination.page = 1
    return load(filters)
  }

  function reset() {
    pagination.page = 1
    tableData.value = []
    total.value = 0
  }

  return { tableData, total, loading, error, pagination, load, onPageChange, onSizeChange, reset }
}
