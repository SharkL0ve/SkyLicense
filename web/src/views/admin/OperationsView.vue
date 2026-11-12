<template>
  <div class="list-view">
    <div class="integrity-strip" :class="integrity?.verified ? 'integrity-ok' : 'integrity-failed'" role="status">
      <div>
        <strong>审计链完整性：</strong>
        <span v-if="integrityLoading">正在校验…</span>
        <span v-else-if="integrity?.verified">已验证（{{ integrity.rowCount }} 条保留记录）</span>
        <span v-else>校验失败或暂不可用</span>
      </div>
      <button type="button" class="integrity-refresh" :disabled="integrityLoading" title="重新校验审计链" @click="loadIntegrity">
        <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h5M20 20v-5h-5M5.07 15A8 8 0 0019 8.93M18.93 9A8 8 0 005 15.07" />
        </svg>
        <span>重新校验</span>
      </button>
    </div>
    <div class="list-toolbar">
      <div class="toolbar-left">
        <div class="search-box">
          <svg class="search-icon" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input v-model="searchQuery" placeholder="筛选当前页日志" aria-label="筛选当前页日志" />
        </div>
      </div>
    </div>

    <div class="list-table-card">
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>操作者</th>
              <th>操作类型</th>
              <th>目标</th>
              <th>结果</th>
              <th>详情</th>
              <th>IP</th>
              <th>UTC 时间</th>
            </tr>
          </thead>
          <tbody v-if="displayedLogs.length > 0">
            <tr v-for="log in displayedLogs" :key="log.id" class="table-row">
              <td>{{ log.id }}</td>
              <td><span style="font-weight: 500;">{{ formatOperator(log) }}</span></td>
              <td>
                <span class="action-tag" :class="getActionClass(log.action)">{{ formatAction(log.action) }}</span>
              </td>
              <td>{{ log.target }}</td>
              <td><span class="outcome-tag" :class="outcomeClass(log.outcome)">{{ formatOutcome(log.outcome) }}</span></td>
              <td class="td-time" style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" :title="log.detail || undefined">{{ log.detail || '-' }}</td>
              <td class="td-time">{{ log.ip }}</td>
              <td class="td-time" :title="log.eventId">{{ log.timestamp }}</td>
            </tr>
          </tbody>
        </table>

        <div v-if="displayedLogs.length === 0 && !loading" class="empty-state">
          <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="opacity: 0.4;">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          <p>暂无操作日志</p>
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
import { ref, computed, onMounted } from 'vue'
import { useTable } from '@/composables/useTable'
import { getAdminOperations, getAdminOperationIntegrity } from '@/api/admin'
import AppPagination from '@/components/AppPagination.vue'
import type { OperationIntegrity, OperationLog } from '@/types'

const searchQuery = ref('')
const integrity = ref<OperationIntegrity | null>(null)
const integrityLoading = ref(false)

const { tableData, total, loading, pagination, load, onPageChange, onSizeChange } = useTable(
  (params) => getAdminOperations(params)
)

const displayedLogs = computed(() => {
  const keyword = searchQuery.value.trim().toLocaleLowerCase()
  if (!keyword) return tableData.value
  return tableData.value.filter((log) =>
    formatOperator(log).toLocaleLowerCase().includes(keyword)
      || log.action.toLocaleLowerCase().includes(keyword)
      || log.target?.toLocaleLowerCase().includes(keyword)
      || log.detail?.toLocaleLowerCase().includes(keyword)
      || log.ip?.toLocaleLowerCase().includes(keyword)
  )
})

function formatOperator(log: OperationLog): string {
  return log.userId > 0 ? `用户 #${log.userId}` : '匿名请求'
}

function getActionClass(action: string): string {
  if (action.includes('DELETE') || action.includes('BAN')) return 'tag-danger'
  if (action.includes('CREATE')) return 'tag-success'
  if (action.includes('UPDATE') || action.includes('TOGGLE')) return 'tag-warning'
  return 'tag-info'
}

const ACTION_LABELS: Record<string, string> = {
  CREATE_LICENSE: '创建许可证',
  UPDATE_LICENSE: '修改许可证',
  DELETE_LICENSE: '删除许可证',
  BAN_LICENSE: '封禁许可证',
  UNBAN_LICENSE: '解封许可证',
  UNBIND_LICENSE: '解绑许可证',
  BATCH_BAN_LICENSE: '批量封禁',
  BATCH_UNBAN_LICENSE: '批量解封',
  BATCH_DELETE_LICENSE: '批量删除',
  CREATE_PROGRAM: '创建程序',
  UPDATE_PROGRAM: '修改程序',
  DELETE_PROGRAM: '删除程序',
  TOGGLE_PROGRAM_STATUS: '切换程序状态',
  UPLOAD_VERSION: '上传版本',
  CREATE_BAN: '创建封禁',
  DELETE_BAN: '解除封禁',
  CREATE_USER: '创建用户',
  UPDATE_USER: '修改用户',
  DELETE_USER: '删除用户',
  TOGGLE_USER_STATUS: '切换用户状态',
  ADMIN_CREATE_LICENSE: '管理员创建许可证',
  CREATE_LICENSE_MULTI: '多程序创建许可证',
}

function formatAction(action: string): string {
  return ACTION_LABELS[action] || action
}

function formatOutcome(outcome: string): string {
  return { ATTEMPT: '处理中', SUCCESS: '成功', REJECTED: '拒绝', LEGACY: '历史迁移' }[outcome] || outcome
}

function outcomeClass(outcome: string): string {
  if (outcome === 'SUCCESS') return 'outcome-success'
  if (outcome === 'REJECTED') return 'outcome-rejected'
  if (outcome === 'ATTEMPT') return 'outcome-attempt'
  return 'outcome-legacy'
}

async function loadIntegrity(): Promise<void> {
  integrityLoading.value = true
  try {
    integrity.value = await getAdminOperationIntegrity()
  } finally {
    integrityLoading.value = false
  }
}

onMounted(() => load())
onMounted(() => loadIntegrity())
</script>

<style scoped lang="scss">
@use '@/styles/list-view.scss';

.action-tag {
  font-size: 0.7rem;
  padding: 0.2rem 0.5rem;
  border-radius: 0.25rem;
  font-weight: 500;
  white-space: nowrap;

  &.tag-danger {
    background-color: rgba(239, 68, 68, 0.1);
    color: #ef4444;
  }

  &.tag-success {
    background-color: rgba(16, 185, 129, 0.1);
    color: #10b981;
  }

  &.tag-warning {
    background-color: rgba(245, 158, 11, 0.1);
    color: #f59e0b;
  }

  &.tag-info {
    background-color: rgba(59, 130, 246, 0.1);
    color: #3b82f6;
  }
}

.integrity-strip {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1rem;
  padding: 0.7rem 0.9rem;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  font-size: 0.82rem;
}

.integrity-ok {
  background: rgba(16, 185, 129, 0.08);
  color: #047857;
}

.integrity-failed {
  background: rgba(239, 68, 68, 0.08);
  color: #b91c1c;
}

.integrity-refresh {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  border: 0;
  background: transparent;
  color: inherit;
  cursor: pointer;
  font: inherit;
}

.integrity-refresh:disabled {
  cursor: wait;
  opacity: 0.6;
}

.outcome-tag {
  display: inline-flex;
  padding: 0.2rem 0.45rem;
  border-radius: 0.25rem;
  font-size: 0.7rem;
  white-space: nowrap;
}

.outcome-success { background: rgba(16, 185, 129, 0.1); color: #047857; }
.outcome-rejected { background: rgba(239, 68, 68, 0.1); color: #b91c1c; }
.outcome-attempt { background: rgba(245, 158, 11, 0.1); color: #b45309; }
.outcome-legacy { background: rgba(107, 114, 128, 0.12); color: #4b5563; }
</style>
