import type { PageResult, PaginationParams } from '@/types'

/**
 * 拉取用于下拉选择的完整小型数据集。后端单页上限为 200，逐页请求避免静默缺项。
 */
export async function fetchAllPages<T>(
  fetchPage: (params: Required<PaginationParams>) => Promise<PageResult<T>>,
  pageSize = 200
): Promise<T[]> {
  const records: T[] = []
  let page = 1

  while (true) {
    const result = await fetchPage({ page, pageSize })
    records.push(...result.records)
    if (page >= result.totalPages || records.length >= result.total || result.records.length === 0) {
      return records
    }
    page += 1
  }
}
