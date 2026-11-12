<template>
  <div class="list-view">
    <!-- Toolbar -->
    <div class="list-toolbar">
      <div class="toolbar-left">
        <div class="search-box">
          <svg class="search-icon" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input v-model="searchQuery" placeholder="筛选当前页用户名" aria-label="筛选当前页用户名" />
        </div>
        <button v-if="selectedIds.length > 0" class="btn-danger" @click="handleBatchDelete">
          批量删除 ({{ selectedIds.length }})
        </button>
      </div>
      <div class="toolbar-right">
        <button class="btn-primary" @click="showCreateDialog">
          <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          创建用户
        </button>
      </div>
    </div>

    <!-- Table -->
    <div class="list-table-card">
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th class="th-checkbox">
                <input type="checkbox" class="custom-checkbox" :checked="isAllSelected" aria-label="选择当前页用户" @change="toggleSelectAll" />
              </th>
              <th>用户</th>
              <th>角色</th>
              <th>最大程序数</th>
              <th>状态</th>
              <th>创建时间</th>
              <th>最后登录</th>
              <th class="th-actions">操作</th>
            </tr>
          </thead>
          <tbody v-if="displayedUsers.length > 0">
            <tr
              v-for="user in displayedUsers"
              :key="user.id"
              class="table-row clickable-row"
              :class="{ selected: selectedIds.includes(user.id) }"
              tabindex="0"
              @click="router.push(`/admin/users/${user.id}`)"
              @keyup.enter="router.push(`/admin/users/${user.id}`)"
            >
              <td class="td-checkbox" @click.stop>
                <input
                  type="checkbox"
                  class="custom-checkbox"
                  :checked="selectedIds.includes(user.id)"
                  :disabled="user.id === authStore.user?.id"
                  :aria-label="`选择用户 ${user.username}`"
                  @change="toggleSelect(user.id)"
                />
              </td>
              <td>
                <div class="user-cell">
                  <div class="user-avatar" :class="user.status === 1 ? 'avatar-active' : 'avatar-banned'">
                    {{ user.username.charAt(0).toUpperCase() }}
                  </div>
                  <div class="user-name-wrapper">
                    <span class="user-name">{{ user.username }}</span>
                    <span v-if="user.status === 0" class="ban-badge">已禁用</span>
                  </div>
                </div>
              </td>
              <td>
                <span class="role-badge" :class="user.role === 'ADMIN' ? 'role-admin' : 'role-user'">
                  {{ user.role === 'ADMIN' ? '管理员' : '用户' }}
                </span>
              </td>
              <td>{{ user.maxPrograms }}</td>
              <td>
                <span class="status-dot" :class="user.status === 1 ? 'dot-active' : 'dot-inactive'"></span>
                {{ user.status === 1 ? '正常' : '禁用' }}
              </td>
              <td class="td-time">{{ user.createTime || '-' }}</td>
              <td class="td-time">{{ user.lastLoginTime || '-' }}</td>
              <td class="td-actions" @click.stop>
                <div class="action-buttons">
                  <button class="action-btn action-edit" title="编辑" @click="showEditDialog(user)">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                  </button>
                  <button class="action-btn" :class="user.status === 1 ? 'action-ban' : 'action-unban'" :title="user.status === 1 ? '禁用' : '启用'" @click="handleToggleStatus(user)">
                    <svg v-if="user.status === 1" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                    <svg v-else width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                  </button>
                  <button
                    class="action-btn action-delete"
                    :disabled="user.id === authStore.user?.id"
                    :title="user.id === authStore.user?.id ? '不能删除当前登录用户' : '删除'"
                    @click="handleDelete(user)"
                  >
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>

        <!-- Empty state -->
        <div v-if="displayedUsers.length === 0 && !loading" class="empty-state">
          <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="opacity: 0.4; margin-bottom: 12px;">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
          </svg>
          <p>未找到用户</p>
        </div>

        <!-- Loading overlay -->
        <div v-if="loading" class="loading-overlay">
          <div class="loading-spinner"></div>
        </div>
      </div>

      <!-- Pagination footer -->
      <AppPagination
        v-model:page="pagination.page"
        v-model:page-size="pagination.pageSize"
        :total="total"
        @update:page="onPageChange"
        @update:page-size="onSizeChange"
      />
    </div>

    <!-- Create/Edit Dialog -->
    <el-dialog v-model="dialogVisible" :title="editingUser ? '编辑用户' : '创建用户'" width="420px" :append-to-body="true">
      <el-form ref="formRef" :model="form" :rules="formRules" label-width="100px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" minlength="3" maxlength="64" placeholder="3–64 位用户名" />
        </el-form-item>
        <el-form-item label="密码" :prop="editingUser ? '' : 'password'">
          <el-input v-model="form.password" type="password" maxlength="128" autocomplete="new-password" show-password :placeholder="editingUser ? '留空不修改' : '请输入初始密码'" />
          <div class="form-help">{{ PASSWORD_HINT }}</div>
        </el-form-item>
        <el-form-item label="角色" prop="role">
          <el-select v-model="form.role" :disabled="editingUser?.id === authStore.user?.id" style="width: 100%;">
            <el-option label="普通用户" value="USER" />
            <el-option label="管理员" value="ADMIN" />
          </el-select>
        </el-form-item>
        <el-form-item label="最大程序数">
          <el-input-number v-model="form.maxPrograms" :min="1" :max="100000" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitLoading" @click="handleSubmit">确认</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { useTable } from '@/composables/useTable'
import * as userApi from '@/api/users'
import type { WebUser } from '@/types'
import AppPagination from '@/components/AppPagination.vue'
import { useAuthStore } from '@/stores/auth'
import { PASSWORD_HINT, passwordRule, usernameRule } from '@/utils/validation'
import { confirmAction } from '@/utils/confirm'

const router = useRouter()
const authStore = useAuthStore()
const searchQuery = ref('')
const selectedIds = ref<number[]>([])

const { tableData, total, loading, pagination, load, onPageChange, onSizeChange } = useTable(
  (params) => userApi.getUsers(params)
)

const displayedUsers = computed(() => {
  const keyword = searchQuery.value.trim().toLocaleLowerCase()
  if (!keyword) return tableData.value
  return tableData.value.filter((user) => user.username.toLocaleLowerCase().includes(keyword))
})

const selectableUsers = computed(() => displayedUsers.value.filter((user) => user.id !== authStore.user?.id))
const isAllSelected = computed(() =>
  selectableUsers.value.length > 0 && selectableUsers.value.every((user) => selectedIds.value.includes(user.id))
)

function toggleSelectAll() {
  if (isAllSelected.value) {
    selectedIds.value = []
  } else {
    selectedIds.value = selectableUsers.value.map((user) => user.id)
  }
}

function toggleSelect(id: number) {
  const idx = selectedIds.value.indexOf(id)
  if (idx >= 0) {
    selectedIds.value.splice(idx, 1)
  } else {
    selectedIds.value.push(id)
  }
}

// Dialog
const dialogVisible = ref(false)
const submitLoading = ref(false)
const editingUser = ref<WebUser | null>(null)
const formRef = ref<FormInstance>()
const form = reactive({
  username: '',
  password: '',
  role: 'USER' as 'USER' | 'ADMIN',
  maxPrograms: 5,
})
const formRules = computed<FormRules>(() => ({
  username: [
    usernameRule(),
  ],
  password: [passwordRule({ required: !editingUser.value })],
  role: [{ required: true, message: '请选择角色', trigger: 'change' }],
}))

function showCreateDialog() {
  editingUser.value = null
  form.username = ''
  form.password = ''
  form.role = 'USER'
  form.maxPrograms = 5
  dialogVisible.value = true
  void nextTick(() => formRef.value?.clearValidate())
}

function showEditDialog(user: WebUser) {
  editingUser.value = user
  form.username = user.username
  form.password = ''
  form.role = user.role
  form.maxPrograms = user.maxPrograms
  dialogVisible.value = true
  void nextTick(() => formRef.value?.clearValidate())
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  submitLoading.value = true
  try {
    if (editingUser.value) {
      const updateData = { username: form.username.trim(), role: form.role, maxPrograms: form.maxPrograms, password: form.password || undefined }
      await userApi.updateUser(editingUser.value.id, updateData)
      ElMessage.success('修改成功')
    } else {
      await userApi.createUser({ ...form, username: form.username.trim() })
      ElMessage.success('创建成功')
    }
    dialogVisible.value = false
    load()
  } finally {
    submitLoading.value = false
  }
}

async function handleToggleStatus(user: WebUser) {
  const newStatus = user.status === 1 ? 0 : 1
  await userApi.toggleUserStatus(user.id, newStatus)
  ElMessage.success(newStatus === 1 ? '已启用' : '已禁用')
  load()
}

async function handleDelete(user: WebUser) {
  if (user.id === authStore.user?.id) return
  if (!await confirmAction(`确定删除用户“${user.username}”吗？该用户的程序、版本、许可证及验证日志将被级联删除。`, '删除用户')) return
  await userApi.deleteUser(user.id)
  ElMessage.success('删除成功')
  selectedIds.value = selectedIds.value.filter(id => id !== user.id)
  load()
}

async function handleBatchDelete() {
  if (!await confirmAction(`确定删除选中的 ${selectedIds.value.length} 个用户吗？关联数据将被级联删除。`, '批量删除用户')) return
  let succeeded = 0
  let failed = 0
  for (const id of selectedIds.value) {
    try {
      await userApi.deleteUser(id)
      succeeded += 1
    } catch {
      failed += 1
    }
  }
  if (failed > 0) ElMessage.warning(`已删除 ${succeeded} 个用户，${failed} 个失败`)
  else ElMessage.success('批量删除成功')
  selectedIds.value = []
  load()
}

onMounted(() => load())
</script>

<style scoped lang="scss">
@use '@/styles/list-view.scss';

.form-help {
  margin-top: 0.35rem;
  color: var(--color-text-muted);
  font-size: 0.75rem;
  line-height: 1.5;
}
</style>
