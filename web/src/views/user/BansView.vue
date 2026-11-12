<template>
  <div class="list-view">
    <div class="list-toolbar">
      <div class="toolbar-left">
        <select v-model="filterType" class="page-size-select" style="padding: 0.5rem 0.75rem; font-size: 0.875rem;" @change="loadBans">
          <option value="">全部类型</option>
          <option value="IP">IP地址</option>
          <option value="HWID">机器码</option>
          <option value="QQ">QQ号</option>
          <option value="CODE">许可证</option>
        </select>
      </div>
      <div class="toolbar-right">
        <button class="btn-primary" @click="showCreateDialog">
          <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          创建封禁
        </button>
      </div>
    </div>

    <div class="list-table-card">
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>类型</th>
              <th>封禁值</th>
              <th>原因</th>
              <th>程序ID</th>
              <th>过期时间</th>
              <th>状态</th>
              <th>创建时间</th>
              <th class="th-actions">操作</th>
            </tr>
          </thead>
          <tbody v-if="tableData.length > 0">
            <tr v-for="ban in tableData" :key="ban.id" class="table-row">
              <td data-label="ID">{{ ban.id }}</td>
              <td data-label="类型">
                <span class="ban-type-badge" :class="`type-${ban.type.toLowerCase()}`">{{ formatBanType(ban.type) }}</span>
              </td>
              <td class="td-ban-value" data-label="封禁值">
                <span class="ban-value" :title="ban.value">{{ ban.value }}</span>
              </td>
              <td class="td-time td-ban-reason" data-label="原因">
                <span class="ban-reason" :title="ban.reason || undefined">{{ ban.reason || '-' }}</span>
              </td>
              <td data-label="程序ID">{{ ban.programId || '-' }}</td>
              <td class="td-time" data-label="过期时间">{{ ban.expirationDate ? formatTime(ban.expirationDate) : '永久' }}</td>
              <td data-label="状态">
                <span class="ban-status-badge" :class="`status-${banStatusTone(ban)}`">
                  {{ banStatusLabel(ban) }}
                </span>
              </td>
              <td class="td-time" data-label="创建时间">{{ formatTime(ban.createTime) }}</td>
              <td class="td-actions" data-label="操作">
                <div class="action-buttons">
                  <button class="action-btn action-delete" :title="ban.status === 1 ? '解除封禁' : '删除记录'" @click="handleDelete(ban)">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>

        <div v-if="tableData.length === 0 && !loading" class="empty-state">
          <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="opacity: 0.4;">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/>
          </svg>
          <p>暂无封禁记录</p>
        </div>

        <div v-if="loading" class="loading-overlay">
          <div class="loading-spinner"></div>
        </div>
      </div>

      <AppPagination
        v-model:page="pagination.page"
        v-model:page-size="pagination.pageSize"
        :total="total"
        @update:page="onPageChange"
        @update:page-size="onSizeChange"
      />
    </div>

    <!-- Create Ban Dialog -->
    <el-dialog v-model="dialogVisible" title="创建封禁" width="450px" :append-to-body="true">
      <el-form ref="formRef" :model="form" :rules="formRules" label-width="80px">
        <el-form-item label="类型" prop="type">
          <el-select v-model="form.type" style="width: 100%;" @change="onBanTypeChange">
            <el-option label="IP地址" value="IP" />
            <el-option label="机器码" value="HWID" />
            <el-option label="QQ号" value="QQ" />
            <el-option label="许可证" value="CODE" />
          </el-select>
        </el-form-item>
        <el-form-item label="封禁值" prop="value">
          <el-input v-model="form.value" :placeholder="banValuePlaceholder" maxlength="256" />
        </el-form-item>
        <el-form-item label="原因">
          <el-input v-model="form.reason" type="textarea" :rows="2" maxlength="1024" placeholder="封禁原因（可选）" />
        </el-form-item>
        <el-form-item label="作用程序" :required="!authStore.isAdmin">
          <el-select
            v-model="form.programId"
            clearable
            filterable
            :placeholder="authStore.isAdmin ? '不选择则为全局规则' : '请选择自己的程序'"
            style="width: 100%;"
          >
            <el-option v-for="program in programs" :key="program.id" :label="`${program.name}（ID: ${program.id}）`" :value="program.id" />
          </el-select>
          <div class="form-help">选择程序后规则仅对该程序生效；只有管理员可以创建全局规则。</div>
        </el-form-item>
        <el-form-item label="过期时间">
          <el-date-picker
            v-model="form.expirationDate"
            type="datetime"
            format="YYYY-MM-DD HH:mm"
            value-format="YYYY-MM-DD-HH:mm"
            placeholder="留空表示永久封禁"
            style="width: 100%;"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitLoading" @click="handleCreate">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, nextTick, onMounted } from 'vue'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { useTable } from '@/composables/useTable'
import * as banApi from '@/api/bans'
import { formatBanType } from '@/utils/format'
import { formatTime } from '@/utils/format'
import type { BanRecord, CreateBanRequest, BanType } from '@/types'
import type { Program } from '@/types'
import AppPagination from '@/components/AppPagination.vue'
import { getPrograms } from '@/api/programs'
import { fetchAllPages } from '@/utils/pagination'
import { confirmAction } from '@/utils/confirm'
import { useAuthStore } from '@/stores/auth'
import { isValidBanValue } from '@/utils/validation'

const filterType = ref('')
const programs = ref<Program[]>([])
const authStore = useAuthStore()

const { tableData, total, loading, pagination, load, onPageChange, onSizeChange } = useTable(
  (params) => banApi.getBans({ ...params, type: filterType.value || undefined })
)

function loadBans() {
  pagination.page = 1
  load()
}

// Create
const dialogVisible = ref(false)
const submitLoading = ref(false)
const formRef = ref<FormInstance>()
const form = reactive<CreateBanRequest>({
  type: 'IP' as BanType,
  value: '',
  reason: '',
  programId: undefined,
  expirationDate: '',
})
const banValuePlaceholder = computed(() => ({
  IP: 'IPv4 或 IPv6 地址',
  HWID: '44 位 Base64 机器码',
  QQ: '1–20 位数字',
  CODE: '许可证',
})[form.type])

const formRules = computed<FormRules>(() => ({
  type: [{ required: true, message: '请选择类型', trigger: 'change' }],
  value: [{
    trigger: 'blur',
    validator: (_rule, value: unknown, callback) => {
      const normalized = typeof value === 'string' ? value.trim() : ''
      if (!normalized) {
        callback(new Error('请输入封禁值'))
        return
      }
      if (!isValidBanValue(form.type, normalized)) {
        const message = {
          IP: '请输入合法的 IPv4 或 IPv6 地址',
          HWID: '请输入有效的 32 字节 Base64 机器码',
          QQ: 'QQ号必须是 1–20 位数字',
          CODE: '许可证格式无效',
        }[form.type]
        callback(new Error(message))
        return
      }
      callback()
    },
  }],
}))

function showCreateDialog() {
  form.type = 'IP'
  form.value = ''
  form.reason = ''
  form.programId = undefined
  form.expirationDate = ''
  dialogVisible.value = true
  void nextTick(() => formRef.value?.clearValidate())
}

function onBanTypeChange() {
  form.value = ''
  formRef.value?.clearValidate('value')
}

function banHasExpired(ban: BanRecord): boolean {
  if (!ban.expirationDate) return false
  const value = ban.expirationDate.trim()
  if (!/^\d{4}-\d{2}-\d{2}-\d{2}:\d{2}$/.test(value)) return false
  const parsed = Date.parse(`${value.slice(0, 10)}T${value.slice(11)}:00`)
  return Number.isFinite(parsed) && parsed <= Date.now()
}

function banStatusLabel(ban: BanRecord): string {
  if (ban.status !== 1) return banHasExpired(ban) ? '已过期' : '已解除'
  return banHasExpired(ban) ? '待清理' : '生效中'
}

function banStatusTone(ban: BanRecord): 'active' | 'expired' | 'removed' {
  if (ban.status !== 1) return banHasExpired(ban) ? 'expired' : 'removed'
  return banHasExpired(ban) ? 'expired' : 'active'
}

async function handleCreate() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  if (!authStore.isAdmin && !form.programId) {
    ElMessage.warning('普通用户创建封禁时必须选择程序')
    return
  }
  submitLoading.value = true
  try {
    const data: CreateBanRequest = { type: form.type, value: form.value.trim() }
    const reason = form.reason?.trim()
    if (reason) data.reason = reason
    if (form.programId) data.programId = form.programId
    if (form.expirationDate) data.expirationDate = form.expirationDate
    await banApi.createBan(data)
    ElMessage.success('封禁创建成功')
    dialogVisible.value = false
    load()
  } finally {
    submitLoading.value = false
  }
}

async function handleDelete(ban: BanRecord) {
  const action = ban.status === 1 ? '解除封禁' : '删除记录'
  if (!await confirmAction(`确定${action}“${ban.value}”吗？`, action)) return
  await banApi.deleteBan(ban.id)
  ElMessage.success(ban.status === 1 ? '已解除封禁' : '记录已删除')
  load()
}

onMounted(async () => {
  void load()
  try {
    programs.value = await fetchAllPages(getPrograms)
  } catch {
    // 列表错误由请求层提示；普通用户仍无法提交无程序作用域的规则。
  }
})
</script>

<style scoped lang="scss">
@use '@/styles/list-view.scss';

.ban-type-badge {
  display: inline-flex;
  align-items: center;
  font-size: 0.7rem;
  padding: 0.2rem 0.5rem;
  border-radius: 0.25rem;
  font-weight: 600;
  text-transform: uppercase;
  white-space: nowrap;

  &.type-ip {
    background-color: rgba(239, 68, 68, 0.1);
    color: #ef4444;
  }

  &.type-hwid {
    background-color: rgba(245, 158, 11, 0.1);
    color: #f59e0b;
  }

  &.type-qq {
    background-color: rgba(59, 130, 246, 0.1);
    color: #3b82f6;
  }

  &.type-code {
    background-color: rgba(139, 92, 246, 0.1);
    color: #8b5cf6;
  }
}

.ban-status-badge {
  display: inline-flex;
  align-items: center;
  min-height: 1.45rem;
  padding: 0.15rem 0.5rem;
  border-radius: 0.25rem;
  font-size: 0.72rem;
  font-weight: 600;
  white-space: nowrap;

  &.status-active {
    color: #047857;
    background: rgba(16, 185, 129, 0.12);
  }

  &.status-expired {
    color: #b45309;
    background: rgba(245, 158, 11, 0.14);
  }

  &.status-removed {
    color: var(--color-text-muted);
    background: var(--color-bg-input);
  }
}

.td-ban-value {
  width: 14rem;
  max-width: 14rem;
}

.ban-value,
.ban-reason {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ban-value {
  max-width: 14rem;
  color: var(--color-text-primary);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.8125rem;
  font-weight: 600;
}

.td-ban-reason {
  width: 9rem;
  max-width: 9rem;
}

.ban-reason {
  max-width: 9rem;
}

@media (max-width: 767px) {
  .table-wrapper {
    overflow: visible;
  }

  .table-wrapper table {
    min-width: 0;

    thead {
      display: none;
    }

    tbody tr {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.75rem 1rem;
      padding: 1rem;

      td {
        display: flex;
        min-width: 0;
        padding: 0;
        flex-direction: column;
        align-items: flex-start;
        gap: 0.25rem;

        &::before {
          content: attr(data-label);
          color: var(--color-text-muted);
          font-size: 0.6875rem;
          font-weight: 600;
        }
      }
    }
  }

  .td-ban-value,
  .td-ban-reason,
  .td-actions {
    grid-column: 1 / -1;
    width: auto;
    max-width: none;
  }

  .td-ban-reason {
    white-space: normal;
  }

  .ban-value,
  .ban-reason {
    max-width: 100%;
  }

  .td-actions {
    flex-direction: row !important;
    align-items: center !important;
    justify-content: space-between;
  }

  .action-buttons {
    opacity: 1;
  }
}

.form-help {
  margin-top: 0.35rem;
  color: var(--color-text-muted);
  font-size: 0.75rem;
  line-height: 1.5;
}
</style>
