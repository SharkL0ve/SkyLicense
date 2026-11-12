<template>
  <div v-loading="loading">
    <div class="page-header">
      <h2 class="page-title">
        <el-button link aria-label="返回程序详情" @click="goBack">
          <el-icon><ArrowLeft /></el-icon>
        </el-button>
        许可证详情
      </h2>
      <el-space v-if="license" wrap>
        <el-button v-if="license?.status === 1" type="danger" @click="handleBan">封禁</el-button>
        <el-button v-else type="success" @click="handleUnban">解封</el-button>
        <el-button type="warning" @click="showEditDialog">编辑</el-button>
        <el-popconfirm title="确定删除该许可证？" @confirm="handleDelete">
          <template #reference>
            <el-button type="danger" plain>删除</el-button>
          </template>
        </el-popconfirm>
      </el-space>
    </div>

    <el-card v-if="license" style="margin-bottom: 16px;" shadow="never">
      <el-descriptions :column="isMobile ? 1 : 2" border class="responsive-descriptions">
        <el-descriptions-item label="许可证" :span="2">
          <code class="license-code">{{ license.code }}</code>
          <el-button link type="primary" @click="copyCode">复制</el-button>
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="license.status === 1 ? 'success' : 'danger'">
            {{ license.status === 1 ? '正常' : '封禁' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="QQ号">{{ license.qq || '-' }}</el-descriptions-item>
        <el-descriptions-item label="可绑定IP数">{{ license.bindableIps === 0 ? '不限制' : license.bindableIps }}</el-descriptions-item>
        <el-descriptions-item label="可绑定机器码数">{{ license.bindableHwids === 0 ? '不限制' : license.bindableHwids }}</el-descriptions-item>
        <el-descriptions-item label="到期时间">{{ license.expirationDate || '永久有效' }}</el-descriptions-item>
        <el-descriptions-item label="每日验证上限">{{ license.maxDailyAuth === 0 ? '不限制' : license.maxDailyAuth }}</el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ license.createTime }}</el-descriptions-item>
        <el-descriptions-item label="最后验证时间">{{ license.lastAuthTime || '-' }}</el-descriptions-item>
        <el-descriptions-item label="最后修改时间">{{ license.lastModifiedTime || '-' }}</el-descriptions-item>
        <el-descriptions-item label="封禁原因" v-if="license.banReason">{{ license.banReason }}</el-descriptions-item>
        <el-descriptions-item label="备注" :span="2">{{ license.notes || '-' }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <!-- Bound IPs -->
    <el-card v-if="license" style="margin-bottom: 16px;">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span>已绑定IP ({{ boundIps.length }})</span>
          <el-button size="small" type="danger" @click="handleUnbindAll" v-if="boundIps.length > 0">清空所有绑定</el-button>
        </div>
      </template>
      <div v-if="boundIps.length > 0" style="display: flex; flex-wrap: wrap; gap: 8px;">
        <el-tag v-for="ip in boundIps" :key="ip" closable @close="handleUnbindIp(ip)">{{ ip }}</el-tag>
      </div>
      <el-empty v-else description="暂无绑定IP" :image-size="60" />
    </el-card>

    <!-- Bound HWIDs -->
    <el-card v-if="license" style="margin-bottom: 16px;">
      <template #header>
        <span>已绑定机器码 ({{ boundHwids.length }})</span>
      </template>
      <div v-if="boundHwids.length > 0" style="display: flex; flex-wrap: wrap; gap: 8px;">
        <el-tag v-for="hwid in boundHwids" :key="hwid" type="warning" closable @close="handleUnbindHwid(hwid)">{{ hwid }}</el-tag>
      </div>
      <el-empty v-else description="暂无绑定机器码" :image-size="60" />
    </el-card>

    <!-- Auth Logs -->
    <el-card>
      <template #header>
        <span>验证历史</span>
      </template>
      <el-table :data="logs" stripe v-loading="logsLoading">
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="hwid" label="机器码" min-width="200" show-overflow-tooltip />
        <el-table-column prop="result" label="结果" width="120">
          <template #default="{ row }">
            <el-tag :type="getResultType(row.result)" size="small">{{ formatAuthResult(row.result) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="timestamp" label="时间" width="160" />
        <template #empty><el-empty description="暂无验证记录" /></template>
      </el-table>
      <AppPagination
        v-model:page="logPagination.page"
        v-model:page-size="logPagination.pageSize"
        :total="logTotal"
        :page-sizes="[10, 20, 50, 100]"
        @update:page="loadLogs"
        @update:page-size="logPagination.page = 1; loadLogs()"
      />
    </el-card>

    <!-- Edit Dialog -->
    <el-dialog v-model="editDialogVisible" title="编辑许可证" width="500px">
      <el-form :model="editForm" label-width="100px">
        <el-form-item label="QQ号">
          <el-input v-model="editForm.qq" maxlength="20" show-word-limit />
          <div class="form-help">留空将清除关联 QQ。</div>
        </el-form-item>
        <el-form-item label="可绑定IP数">
          <el-input-number v-model="editForm.bindableIps" :min="0" />
        </el-form-item>
        <el-form-item label="可绑定机器码">
          <el-input-number v-model="editForm.bindableHwids" :min="0" />
        </el-form-item>
        <el-form-item label="到期时间">
          <el-date-picker
            v-model="editForm.expirationDate"
            type="datetime"
            format="YYYY-MM-DD HH:mm"
            value-format="YYYY-MM-DD-HH:mm"
            placeholder="留空表示永久有效"
            style="width: 100%;"
          />
        </el-form-item>
        <el-form-item label="每日验证上限">
          <el-input-number v-model="editForm.maxDailyAuth" :min="0" :max="1000000" />
          <span style="margin-left: 8px; color: #9ca3af; font-size: 12px;">0 = 不限制</span>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="editForm.notes" type="textarea" :rows="2" maxlength="2048" show-word-limit />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="editLoading" @click="handleEdit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as licenseApi from '@/api/licenses'
import { authResultTone, formatAuthResult, splitList } from '@/utils/format'
import type { License, AuthLog, UpdateLicenseRequest } from '@/types'
import AppPagination from '@/components/AppPagination.vue'
import { ArrowLeft } from '@element-plus/icons-vue'
import { confirmAction } from '@/utils/confirm'
import { useMediaQuery } from '@/composables/useMediaQuery'
import { isValidQq } from '@/utils/validation'

const router = useRouter()
const route = useRoute()
const code = route.params.code as string
const isMobile = useMediaQuery('(max-width: 640px)')

const loading = ref(true)
const license = ref<License | null>(null)

const boundIps = computed(() => splitList(license.value?.ips))
const boundHwids = computed(() => splitList(license.value?.hwids))

// Logs
const logs = ref<AuthLog[]>([])
const logTotal = ref(0)
const logsLoading = ref(false)
const logPagination = reactive({ page: 1, pageSize: 20 })

// Edit
const editDialogVisible = ref(false)
const editLoading = ref(false)
const editForm = reactive<UpdateLicenseRequest>({
  qq: '',
  bindableIps: 1,
  bindableHwids: 0,
  expirationDate: '',
  maxDailyAuth: 0,
  notes: '',
})

function getResultType(result: string): 'success' | 'warning' | 'danger' {
  return authResultTone(result)
}

async function loadLicense() {
  loading.value = true
  try {
    license.value = await licenseApi.getLicenseDetail(code)
    await loadLogs()
  } finally {
    loading.value = false
  }
}

function goBack() {
  if (license.value) {
    void router.push(`/programs/${license.value.programId}`)
  } else {
    void router.push('/programs')
  }
}

async function copyCode() {
  try {
    await navigator.clipboard.writeText(code)
    ElMessage.success('许可证已复制')
  } catch {
    ElMessage.warning('复制失败，请手动复制')
  }
}

async function loadLogs() {
  logsLoading.value = true
  try {
    const result = await licenseApi.getLicenseLogs(code, logPagination)
    logs.value = result.records
    logTotal.value = result.total
  } finally {
    logsLoading.value = false
  }
}

async function handleBan() {
  const { value: reason } = await ElMessageBox.prompt('请输入封禁原因（可选）', '封禁许可证', {
    confirmButtonText: '确认封禁',
    cancelButtonText: '取消',
  }).catch(() => ({ value: null }))
  if (reason === null) return
  await licenseApi.banLicense(code, reason || undefined)
  ElMessage.success('已封禁')
  loadLicense()
}

async function handleUnban() {
  await licenseApi.unbanLicense(code)
  ElMessage.success('已解封')
  loadLicense()
}

async function handleDelete() {
  await licenseApi.deleteLicense(code)
  ElMessage.success('删除成功')
  router.back()
}

async function handleUnbindIp(ip: string) {
  await licenseApi.unbindLicense(code, { ip })
  ElMessage.success('已解绑')
  loadLicense()
}

async function handleUnbindHwid(hwid: string) {
  await licenseApi.unbindLicense(code, { hwid })
  ElMessage.success('已解绑')
  loadLicense()
}

async function handleUnbindAll() {
  if (!await confirmAction('确定清空全部 IP 与机器码绑定吗？此操作不可撤销。', '清空全部绑定')) return
  await licenseApi.unbindLicense(code, { all: true })
  ElMessage.success('已清空')
  loadLicense()
}

function showEditDialog() {
  if (!license.value) return
  editForm.qq = license.value.qq || ''
  editForm.bindableIps = license.value.bindableIps
  editForm.bindableHwids = license.value.bindableHwids
  editForm.expirationDate = license.value.expirationDate || ''
  editForm.maxDailyAuth = license.value.maxDailyAuth
  editForm.notes = license.value.notes || ''
  editDialogVisible.value = true
}

async function handleEdit() {
  const requestedQq = editForm.qq?.trim() || ''
  if (requestedQq && !isValidQq(requestedQq)) {
    ElMessage.warning('QQ号必须是1–20位数字')
    return
  }
  editLoading.value = true
  try {
    const data: UpdateLicenseRequest = {
      bindableIps: editForm.bindableIps,
      bindableHwids: editForm.bindableHwids,
      qq: requestedQq,
      expirationDate: editForm.expirationDate || '',
      maxDailyAuth: editForm.maxDailyAuth,
      notes: editForm.notes,
    }
    await licenseApi.updateLicense(code, data)
    ElMessage.success('修改成功')
    editDialogVisible.value = false
    loadLicense()
  } finally {
    editLoading.value = false
  }
}

onMounted(() => {
  if (!code.trim()) {
    void router.replace('/programs')
    return
  }
  void loadLicense()
})
</script>

<style scoped lang="scss">
.license-code {
  margin-right: 0.75rem;
  overflow-wrap: anywhere;
  font-size: 0.875rem;
}

.form-help {
  margin-top: 0.35rem;
  color: var(--color-text-muted);
  font-size: 0.75rem;
}
</style>
