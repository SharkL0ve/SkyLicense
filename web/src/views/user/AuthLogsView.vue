<template>
  <div class="list-view">
    <div class="list-toolbar">
      <div class="toolbar-left">
        <div class="search-box">
          <svg class="search-icon" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input v-model="filters.code" maxlength="256" placeholder="搜索许可证..." @keyup.enter="handleSearch" />
        </div>
        <input v-model="filters.ip" class="filter-input" maxlength="64" placeholder="IP地址" @keyup.enter="handleSearch" />
        <input v-model="filters.hwid" class="filter-input" maxlength="256" placeholder="机器码" @keyup.enter="handleSearch" />
        <el-select v-model="filters.programId" class="program-filter" clearable filterable placeholder="全部程序" @change="handleSearch">
          <el-option v-for="program in programs" :key="program.id" :label="program.name" :value="program.id" />
        </el-select>
        <select v-model="filters.result" class="page-size-select filter-select" @change="handleSearch">
          <option value="">全部结果</option>
          <option v-for="item in AUTH_RESULTS" :key="item.value" :value="item.value">{{ item.label }}</option>
        </select>
        <el-date-picker
          v-model="dateRange"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          format="YYYY-MM-DD HH:mm"
          value-format="YYYY-MM-DD-HH:mm"
          class="date-filter"
        />
        <button class="btn-primary" style="padding: 0.4rem 0.75rem;" @click="handleSearch">搜索</button>
        <button class="btn-reset" @click="resetFilters">重置</button>
      </div>
    </div>

    <div class="list-table-card">
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>许可证</th>
              <th>IP</th>
              <th>机器码</th>
              <th>结果</th>
              <th>程序ID</th>
              <th>时间</th>
            </tr>
          </thead>
          <tbody v-if="tableData.length > 0">
            <tr v-for="log in tableData" :key="log.id" class="table-row">
              <td>{{ log.id }}</td>
              <td>
                <span class="code-text" @click="router.push({ name: 'LicenseDetail', params: { code: log.code } })">{{ log.code }}</span>
              </td>
              <td>{{ log.ip || '-' }}</td>
              <td class="td-time" style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" :title="log.hwid">{{ log.hwid || '-' }}</td>
              <td>
                <span class="result-badge" :class="getResultClass(log.result)">{{ formatAuthResult(log.result) }}</span>
              </td>
              <td>{{ log.programId }}</td>
              <td class="td-time">{{ log.timestamp }}</td>
            </tr>
          </tbody>
        </table>

        <div v-if="tableData.length === 0 && !loading" class="empty-state">
          <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="opacity: 0.4;">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          <p>暂无验证记录</p>
        </div>

        <div v-if="loading" class="loading-overlay">
          <div class="loading-spinner"></div>
        </div>
      </div>

      <AppPagination
        v-model:page="pagination.page"
        v-model:page-size="pagination.pageSize"
        :total="total"
        :page-sizes="[20, 50, 100]"
        @update:page="onPageChange"
        @update:page-size="onSizeChange"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useTable } from '@/composables/useTable'
import { getAuthLogs } from '@/api/licenses'
import { authResultTone, formatAuthResult } from '@/utils/format'
import type { AuthLogQuery } from '@/types'
import type { Program } from '@/types'
import AppPagination from '@/components/AppPagination.vue'
import { getPrograms } from '@/api/programs'
import { fetchAllPages } from '@/utils/pagination'
import { AUTH_RESULTS } from '@/utils/constants'

const router = useRouter()
const programs = ref<Program[]>([])
const dateRange = ref<[string, string] | null>(null)

const filters = reactive<AuthLogQuery>({
  code: '',
  ip: '',
  hwid: '',
  result: '',
})

const { tableData, total, loading, pagination, load, onPageChange, onSizeChange } = useTable(
  (params) => {
    const cleanFilters = Object.fromEntries(
      Object.entries(filters).filter(([, v]) => v !== '' && v !== undefined && v !== null)
    ) as AuthLogQuery
    if (dateRange.value?.length === 2) {
      cleanFilters.startTime = dateRange.value[0]
      cleanFilters.endTime = dateRange.value[1]
    }
    return getAuthLogs({ ...params, ...cleanFilters })
  }
)

function handleSearch() {
  pagination.page = 1
  load()
}

function resetFilters() {
  filters.code = ''
  filters.ip = ''
  filters.hwid = ''
  filters.result = ''
  filters.programId = undefined
  dateRange.value = null
  pagination.page = 1
  load()
}

function getResultClass(result: string): string {
  return `result-${authResultTone(result)}`
}

onMounted(async () => {
  void load()
  try {
    programs.value = await fetchAllPages(getPrograms)
  } catch {
    // 程序下拉加载失败不影响日志查询。
  }
})
</script>

<style scoped lang="scss">
@use '@/styles/list-view.scss';

.filter-input {
  width: 120px;
  padding: 0.5rem 0.75rem;
  border: 1px solid #e5e7eb;
  border-radius: 0.5rem;
  outline: none;
  font-size: 0.8rem;
  background-color: #f3f4f6;
  color: #1f2937;
  transition: all 0.2s;

  &::placeholder { color: #9ca3af; }
  &:focus {
    border-color: #5bcffa;
    background-color: white;
    box-shadow: 0 0 0 2px rgba(91, 207, 250, 0.2);
  }
}

.filter-select {
  padding: 0.5rem 0.75rem;
  font-size: 0.8rem;
}

.program-filter {
  width: 150px;
}

.date-filter {
  max-width: 330px;
}

.btn-reset {
  padding: 0.4rem 0.75rem;
  border: 1px solid #d1d5db;
  border-radius: 0.5rem;
  background: white;
  color: #6b7280;
  font-size: 0.8rem;
  cursor: pointer;
  transition: all 0.2s;

  &:hover {
    border-color: #9ca3af;
    color: #1f2937;
  }
}

.code-text {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 0.8rem;
  color: #5bcffa;
  cursor: pointer;
  transition: color 0.2s;

  &:hover {
    color: #4ab8e6;
    text-decoration: underline;
  }
}

.result-badge {
  font-size: 0.7rem;
  padding: 0.2rem 0.5rem;
  border-radius: 0.25rem;
  font-weight: 500;
  white-space: nowrap;

  &.result-success {
    background-color: rgba(16, 185, 129, 0.1);
    color: #10b981;
  }

  &.result-warning {
    background-color: rgba(245, 158, 11, 0.1);
    color: #f59e0b;
  }

  &.result-danger {
    background-color: rgba(239, 68, 68, 0.1);
    color: #ef4444;
  }
}
</style>
