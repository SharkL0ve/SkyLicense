<template>
  <div v-loading="loading">
    <div class="page-header">
      <h2 class="page-title">
        <el-button link @click="router.push('/admin/users')">
          <el-icon><ArrowLeft /></el-icon>
        </el-button>
        用户详情
      </h2>
    </div>

    <el-card v-if="user" style="margin-bottom: 16px;" shadow="never">
      <el-descriptions :column="isMobile ? 1 : 3" border class="responsive-descriptions">
        <el-descriptions-item label="ID">{{ user.id }}</el-descriptions-item>
        <el-descriptions-item label="用户名">{{ user.username }}</el-descriptions-item>
        <el-descriptions-item label="角色">
          <el-tag :type="user.role === 'ADMIN' ? 'danger' : 'info'" size="small">
            {{ user.role === 'ADMIN' ? '管理员' : '用户' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="user.status === 1 ? 'success' : 'danger'" size="small">
            {{ user.status === 1 ? '正常' : '禁用' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="最大程序数">{{ user.maxPrograms }}</el-descriptions-item>
        <el-descriptions-item label="邮箱">{{ user.email || '-' }}</el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ user.createTime }}</el-descriptions-item>
        <el-descriptions-item label="最后登录">{{ user.lastLoginTime || '-' }}</el-descriptions-item>
        <el-descriptions-item label="MFA">
          <el-tag :type="user.mfaEnabled === 1 ? 'success' : 'info'" size="small">
            {{ user.mfaEnabled === 1 ? '已启用' : '未启用' }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>
      <div v-if="user.mfaEnabled === 1 && user.id !== authStore.user?.id" class="detail-actions">
        <el-button type="warning" plain :icon="Key" @click="resetDialogVisible = true">
          管理员重置 MFA
        </el-button>
      </div>
    </el-card>

    <!-- Operation Logs -->
    <el-card>
      <template #header><span>操作历史</span></template>
      <el-table :data="operations" stripe v-loading="opsLoading">
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="action" label="操作" width="180">
          <template #default="{ row }">
            <el-tag :type="getActionTagType(row.action)" size="small">{{ formatAction(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="target" label="目标" width="100" />
        <el-table-column prop="detail" label="详情" min-width="300" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="timestamp" label="时间" width="160" />
      </el-table>
      <AppPagination
        v-model:page="opsPagination.page"
        v-model:page-size="opsPagination.pageSize"
        :total="opsTotal"
        @update:page="loadOperations"
        @update:page-size="opsPagination.page = 1; loadOperations()"
      />
    </el-card>

    <el-dialog v-model="resetDialogVisible" title="管理员重置 MFA" width="420px" destroy-on-close>
      <el-form :model="resetForm" label-position="top">
        <el-form-item label="当前管理员密码">
          <el-input v-model="resetForm.password" type="password" autocomplete="current-password" maxlength="128" show-password />
        </el-form-item>
        <el-form-item label="管理员验证码或恢复码">
          <el-input v-model="resetForm.factor" autocomplete="one-time-code" maxlength="64" placeholder="管理员未启用 MFA 时可留空" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="resetDialogVisible = false">取消</el-button>
        <el-button type="warning" :loading="resetLoading" :disabled="!resetForm.password" @click="resetMfa">
          确认重置
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import * as userApi from '@/api/users'
import type { WebUser, OperationLog } from '@/types'
import AppPagination from '@/components/AppPagination.vue'
import { useMediaQuery } from '@/composables/useMediaQuery'
import { ArrowLeft } from '@element-plus/icons-vue'
import { Key } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'

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
  ADMIN_RESET_MFA: '管理员重置 MFA',
  ADMIN_CREATE_LICENSE: '管理员创建许可证',
  CREATE_LICENSE_MULTI: '多程序创建许可证',
}

function formatAction(action: string): string {
  return ACTION_LABELS[action] || action
}

type TagType = 'primary' | 'success' | 'warning' | 'info' | 'danger'

function getActionTagType(action: string): TagType {
  if (action.includes('DELETE') || action.includes('BAN')) return 'danger'
  if (action.includes('CREATE')) return 'success'
  if (action.includes('UPDATE') || action.includes('TOGGLE')) return 'warning'
  return 'info'
}

const router = useRouter()
const route = useRoute()
const isMobile = useMediaQuery('(max-width: 640px)')
const userId = Number(route.params.id)
const authStore = useAuthStore()

const loading = ref(true)
const user = ref<WebUser | null>(null)

const operations = ref<OperationLog[]>([])
const opsTotal = ref(0)
const opsLoading = ref(false)
const opsPagination = reactive({ page: 1, pageSize: 20 })
const resetDialogVisible = ref(false)
const resetLoading = ref(false)
const resetForm = reactive({ password: '', factor: '' })

async function loadUser() {
  loading.value = true
  try {
    user.value = await userApi.getUser(userId)
    await loadOperations()
  } finally {
    loading.value = false
  }
}

async function loadOperations() {
  opsLoading.value = true
  try {
    const result = await userApi.getUserOperations(userId, opsPagination)
    operations.value = result.records
    opsTotal.value = result.total
  } finally {
    opsLoading.value = false
  }
}

async function resetMfa() {
  resetLoading.value = true
  try {
    await userApi.resetUserMfa(userId, {
      password: resetForm.password,
      factor: resetForm.factor || undefined,
    })
    ElMessage.success('MFA 已重置')
    resetDialogVisible.value = false
    resetForm.password = ''
    resetForm.factor = ''
    await loadUser()
  } finally {
    resetLoading.value = false
  }
}

onMounted(() => {
  if (!Number.isSafeInteger(userId) || userId <= 0) {
    void router.replace('/admin/users')
    return
  }
  void loadUser()
})
</script>
