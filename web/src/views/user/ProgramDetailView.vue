<template>
  <div v-loading="pageLoading">
    <div class="page-header">
      <h2 class="page-title">
        <el-button link @click="router.push('/programs')">
          <el-icon><ArrowLeft /></el-icon>
        </el-button>
        {{ program?.name || '程序详情' }}
        <el-tag v-if="program" :type="program.status === 1 ? 'success' : 'danger'" size="small" style="margin-left: 8px;">
          {{ program.status === 1 ? '正常' : '禁用' }}
        </el-tag>
      </h2>
    </div>

    <el-card v-if="program" style="margin-bottom: 16px;" shadow="never">
      <el-descriptions :column="isMobile ? 1 : 3" border class="responsive-descriptions">
        <el-descriptions-item label="ID">{{ program.id }}</el-descriptions-item>
        <el-descriptions-item label="名称">{{ program.name }}</el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ program.createTime }}</el-descriptions-item>
        <el-descriptions-item label="描述" :span="3">{{ program.description || '-' }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-tabs v-model="activeTab" type="border-card" @tab-change="handleTabChange">
      <!-- Versions Tab -->
      <el-tab-pane label="版本管理" name="versions">
        <div style="margin-bottom: 12px;">
          <el-button type="primary" size="small" @click="showUploadDialog">
            <el-icon><Upload /></el-icon>
            上传新版本
          </el-button>
        </div>
        <el-table :data="versions" stripe>
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="version" label="版本号" width="120" />
          <el-table-column prop="fileName" label="文件名" min-width="200" />
          <el-table-column prop="entryClass" label="入口类" min-width="200" show-overflow-tooltip />
          <el-table-column prop="uploadTime" label="上传时间" width="160" />
          <el-table-column label="操作" width="80">
            <template #default="{ row }">
              <el-popconfirm title="确定删除该版本？" @confirm="handleDeleteVersion(row.id)">
                <template #reference>
                  <el-button link type="danger" size="small">删除</el-button>
                </template>
              </el-popconfirm>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- Licenses Tab -->
      <el-tab-pane label="许可证管理" name="licenses">
        <div class="filter-bar">
          <el-input v-model="licenseFilter.keyword" placeholder="搜索许可证/QQ/备注" maxlength="256" clearable style="width: 220px;" @clear="searchLicenses" @keyup.enter="searchLicenses" />
          <el-select v-model="licenseFilter.status" placeholder="状态" clearable style="width: 120px;" @change="searchLicenses">
            <el-option label="正常" value="active" />
            <el-option label="封禁" value="banned" />
          </el-select>
          <el-input v-model="licenseFilter.qq" placeholder="QQ号" maxlength="128" clearable style="width: 140px;" @clear="searchLicenses" @keyup.enter="searchLicenses" />
          <el-input v-model="licenseFilter.ip" placeholder="IP地址" maxlength="64" clearable style="width: 140px;" @clear="searchLicenses" @keyup.enter="searchLicenses" />
          <el-input v-model="licenseFilter.hwid" placeholder="机器码" maxlength="256" clearable style="width: 140px;" @clear="searchLicenses" @keyup.enter="searchLicenses" />
          <el-button type="primary" @click="searchLicenses">搜索</el-button>
          <el-button @click="resetFilter">重置</el-button>
        </div>

        <div class="table-toolbar" v-if="selectedLicenses.length > 0">
          <span style="color: #909399; font-size: 13px;">已选 {{ selectedLicenses.length }} 项</span>
          <el-button size="small" type="danger" @click="handleBatchBan">批量封禁</el-button>
          <el-button size="small" type="success" @click="handleBatchUnban">批量解封</el-button>
          <el-button size="small" type="danger" plain @click="handleBatchDelete">批量删除</el-button>
        </div>

        <div style="margin-bottom: 12px;">
          <el-button type="primary" size="small" :disabled="program?.status !== 1" @click="showLicenseDialog">
            <el-icon><Plus /></el-icon>
            创建许可证
          </el-button>
        </div>

        <el-table :data="licenses" stripe @selection-change="onSelectionChange" v-loading="licensesLoading" @row-click="onLicenseRowClick" row-class-name="clickable-row">
          <el-table-column type="selection" width="40" />
          <el-table-column prop="code" label="许可证" min-width="280" show-overflow-tooltip />
          <el-table-column prop="qq" label="QQ" width="120" />
          <el-table-column prop="status" label="状态" width="80">
            <template #default="{ row }">
              <el-tag :type="row.status === 1 ? 'success' : 'danger'" size="small">
                {{ row.status === 1 ? '正常' : '封禁' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="bindableIps" label="IP限制" width="80" />
          <el-table-column prop="bindableHwids" label="机器码限制" width="100" />
          <el-table-column prop="createTime" label="创建时间" width="160" />
          <el-table-column prop="lastAuthTime" label="最后验证" width="160" />
          <el-table-column label="操作" width="80" fixed="right">
            <template #default="{ row }">
              <el-popconfirm title="确定删除？" @confirm="handleDeleteLicense(row.code)">
                <template #reference>
                  <el-button link type="danger" size="small" @click.stop>删除</el-button>
                </template>
              </el-popconfirm>
            </template>
          </el-table-column>
        </el-table>

        <AppPagination
          v-model:page="licensePagination.page"
          v-model:page-size="licensePagination.pageSize"
          :total="licenseTotal"
          @update:page="loadLicenses"
          @update:page-size="licensePagination.page = 1; loadLicenses()"
        />
      </el-tab-pane>

      <el-tab-pane label="程序验证日志" name="authLogs" lazy>
        <div class="filter-bar">
          <el-input v-model="authLogFilters.code" placeholder="许可证" maxlength="256" clearable />
          <el-input v-model="authLogFilters.ip" placeholder="IP 地址" maxlength="64" clearable />
          <el-input v-model="authLogFilters.hwid" placeholder="机器码" maxlength="256" clearable />
          <el-select v-model="authLogFilters.result" placeholder="验证结果" clearable>
            <el-option v-for="item in AUTH_RESULTS" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
          <el-button type="primary" @click="searchProgramAuthLogs">查询</el-button>
          <el-button @click="resetProgramAuthLogs">重置</el-button>
        </div>
        <el-table :data="programAuthLogs" stripe v-loading="authLogsLoading">
          <el-table-column prop="code" label="许可证" min-width="240" show-overflow-tooltip />
          <el-table-column prop="ip" label="IP" width="150" />
          <el-table-column prop="hwid" label="机器码" min-width="180" show-overflow-tooltip />
          <el-table-column prop="result" label="结果" width="130">
            <template #default="{ row }">
              <el-tag :type="getAuthResultType(row.result)" size="small">{{ formatAuthResult(row.result) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="timestamp" label="时间" width="170" />
          <template #empty><el-empty description="暂无验证日志" /></template>
        </el-table>
        <AppPagination
          v-model:page="authLogPagination.page"
          v-model:page-size="authLogPagination.pageSize"
          :total="authLogTotal"
          @update:page="loadProgramAuthLogs"
          @update:page-size="authLogPagination.page = 1; loadProgramAuthLogs()"
        />
      </el-tab-pane>
    </el-tabs>

    <!-- Upload Version Dialog -->
    <el-dialog v-model="uploadDialogVisible" title="上传新版本" width="500px">
      <el-form :model="uploadForm" label-width="80px">
        <el-form-item label="版本号" required>
          <el-input v-model="uploadForm.version" maxlength="64" placeholder="例如：1.0.0" />
          <div class="form-help">1–64 位安全 ASCII 字符，可使用字母、数字、点、下划线、加号和连字符。</div>
        </el-form-item>
        <el-form-item label="JAR文件" required>
          <el-upload
            ref="uploadRef"
            :auto-upload="false"
            :limit="1"
            accept=".jar"
            :on-change="onFileChange"
            :on-remove="onFileRemove"
            :on-exceed="onFileExceed"
          >
            <el-button type="primary">选择文件</el-button>
            <template #tip>
              <div class="el-upload__tip">仅支持有效的 .jar 文件，最大 64 MiB，且必须包含有效 settings.yml</div>
            </template>
          </el-upload>
        </el-form-item>
      </el-form>
      <el-progress v-if="uploadLoading" :percentage="uploadProgress" :stroke-width="8" />
      <template #footer>
        <el-button @click="uploadDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="uploadLoading" @click="handleUpload">上传</el-button>
      </template>
    </el-dialog>

    <!-- Create License Dialog -->
    <el-dialog v-model="licenseDialogVisible" title="创建许可证" width="520px">
      <el-form ref="licenseFormRef" :model="licenseForm" label-width="100px">
        <el-form-item label="目标程序">
          <el-select
            v-model="licenseForm.programIds"
            multiple
            filterable
            placeholder="选择程序（可多选）"
            style="width: 100%;"
          >
            <el-option
              v-for="p in userPrograms"
              :key="p.id"
              :label="p.name"
              :value="p.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="许可证">
           <el-input v-model="licenseForm.code" maxlength="256" placeholder="留空自动生成；多程序时追加程序 ID" />
        </el-form-item>
        <el-form-item label="QQ号">
           <el-input v-model="licenseForm.qq" placeholder="关联QQ号（可选，1–20位数字）" maxlength="20" show-word-limit />
        </el-form-item>
        <el-form-item label="绑定限制">
          <el-select v-model="licenseForm.bindType" style="width: 100%;" @change="onBindTypeChange">
            <el-option label="服务端默认 — 1 个 IP，不限制机器码" value="server_default" />
            <el-option label="单机授权 — 一台机器一个IP" value="single" />
            <el-option label="多IP单机 — 一台机器，允许IP变化" value="multi_ip" />
            <el-option label="不限IP限机器 — 不管IP，限制机器数" value="limit_hwid" />
            <el-option label="完全不限 — 不检查IP和机器码" value="unlimited" />
            <el-option label="网吧授权 — 多IP，不限机器码" value="cafe" />
            <el-option label="自定义" value="custom" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="licenseForm.bindType === 'multi_ip' || licenseForm.bindType === 'cafe' || licenseForm.bindType === 'custom'" label="可绑定IP数">
          <el-input-number v-model="licenseForm.bindableIps" :min="0" :max="999" />
          <span style="margin-left: 8px; color: #9ca3af; font-size: 12px;">0 = 不限制</span>
        </el-form-item>
        <el-form-item v-if="licenseForm.bindType === 'limit_hwid' || licenseForm.bindType === 'custom'" label="可绑定机器码">
          <el-input-number v-model="licenseForm.bindableHwids" :min="0" :max="999" />
          <span style="margin-left: 8px; color: #9ca3af; font-size: 12px;">0 = 不限制</span>
        </el-form-item>
        <el-form-item label="到期时间">
          <el-date-picker
            v-model="licenseForm.expirationDate"
            type="datetime"
            format="YYYY-MM-DD HH:mm"
            value-format="YYYY-MM-DD-HH:mm"
            placeholder="留空表示永久有效"
            style="width: 100%;"
          />
        </el-form-item>
        <el-form-item label="每日验证上限">
          <el-input-number v-model="licenseForm.maxDailyAuth" :min="0" :max="1000000" />
          <span style="margin-left: 8px; color: #9ca3af; font-size: 12px;">0 = 不限制，仅统计启动认证</span>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="licenseForm.notes" type="textarea" :rows="2" placeholder="备注信息（可选）" maxlength="2048" show-word-limit />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="licenseDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="licenseSubmitLoading" @click="handleCreateLicense">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, nextTick } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as programApi from '@/api/programs'
import * as licenseApi from '@/api/licenses'
import type {
  Program,
  ProgramVersion,
  License,
  LicenseFilter,
  PaginationParams,
  CreateLicenseRequest,
  MultiCreateLicenseRequest,
  AdminCreateLicenseRequest,
  AuthLog,
  AuthLogQuery,
} from '@/types'
import type { UploadFile, UploadInstance } from 'element-plus'
import AppPagination from '@/components/AppPagination.vue'
import { fetchAllPages } from '@/utils/pagination'
import { AUTH_RESULTS } from '@/utils/constants'
import { authResultTone, formatAuthResult } from '@/utils/format'
import { isValidLicenseCode, isValidQq, MAX_JAR_SIZE, VERSION_PATTERN } from '@/utils/validation'
import { useAuthStore } from '@/stores/auth'
import { adminCreateLicense } from '@/api/admin'
import { ArrowLeft, Plus, Upload } from '@element-plus/icons-vue'
import { confirmAction } from '@/utils/confirm'
import { useMediaQuery } from '@/composables/useMediaQuery'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const isMobile = useMediaQuery('(max-width: 640px)')
const programId = Number(route.params.id)

const pageLoading = ref(true)
const program = ref<Program | null>(null)
const versions = ref<ProgramVersion[]>([])
const activeTab = ref('licenses')

// Versions
const uploadDialogVisible = ref(false)
const uploadLoading = ref(false)
const uploadProgress = ref(0)
const uploadRef = ref<UploadInstance>()
const uploadForm = reactive({ version: '', file: null as File | null })

// Licenses
const licenses = ref<License[]>([])
const licenseTotal = ref(0)
const licensesLoading = ref(false)
const licensePagination = reactive({ page: 1, pageSize: 20 })
const licenseFilter = reactive<LicenseFilter>({ keyword: '', status: '', qq: '', ip: '', hwid: '' })
const selectedLicenses = ref<License[]>([])

const programAuthLogs = ref<AuthLog[]>([])
const authLogTotal = ref(0)
const authLogsLoading = ref(false)
const authLogsLoaded = ref(false)
const authLogPagination = reactive({ page: 1, pageSize: 20 })
const authLogFilters = reactive<AuthLogQuery>({ code: '', ip: '', hwid: '', result: '' })

// Create License
const licenseDialogVisible = ref(false)
const licenseSubmitLoading = ref(false)
const licenseFormRef = ref()
const userPrograms = ref<Program[]>([])
const licenseForm = reactive({
  programIds: [] as number[],
  bindType: 'server_default' as string,
  code: '',
  qq: '',
  bindableIps: 1,
  bindableHwids: 0,
  expirationDate: '',
  maxDailyAuth: 0,
  notes: '',
})

async function loadProgram() {
  pageLoading.value = true
  try {
    program.value = await programApi.getProgram(programId)
    userPrograms.value = await fetchAllPages(programApi.getPrograms)
    await loadVersions()
    await loadLicenses()
  } finally {
    pageLoading.value = false
  }
}

async function loadVersions() {
  versions.value = await programApi.getProgramVersions(programId)
}

async function loadLicenses() {
  licensesLoading.value = true
  try {
    const params = { ...licensePagination, ...licenseFilter }
    // Remove empty string values
    const cleanParams = Object.fromEntries(
      Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null)
    ) as PaginationParams & LicenseFilter
    const result = await licenseApi.getLicenses(programId, cleanParams)
    licenses.value = result.records
    licenseTotal.value = result.total
  } finally {
    licensesLoading.value = false
  }
}

function searchLicenses() {
  licensePagination.page = 1
  void loadLicenses()
}

async function loadProgramAuthLogs() {
  authLogsLoading.value = true
  try {
    const filters = Object.fromEntries(
      Object.entries(authLogFilters).filter(([, value]) => value !== '' && value != null)
    ) as AuthLogQuery
    const result = await programApi.getProgramAuthLogs(programId, { ...authLogPagination, ...filters })
    programAuthLogs.value = result.records
    authLogTotal.value = result.total
    authLogsLoaded.value = true
  } finally {
    authLogsLoading.value = false
  }
}

function searchProgramAuthLogs() {
  authLogPagination.page = 1
  void loadProgramAuthLogs()
}

function resetProgramAuthLogs() {
  Object.assign(authLogFilters, { code: '', ip: '', hwid: '', result: '' })
  searchProgramAuthLogs()
}

function handleTabChange(name: string | number) {
  if (name === 'authLogs' && !authLogsLoaded.value) void loadProgramAuthLogs()
}

function getAuthResultType(result: string): 'success' | 'warning' | 'danger' {
  return authResultTone(result)
}

function resetFilter() {
  licenseFilter.keyword = ''
  licenseFilter.status = ''
  licenseFilter.qq = ''
  licenseFilter.ip = ''
  licenseFilter.hwid = ''
  licensePagination.page = 1
  loadLicenses()
}

function onSelectionChange(selection: License[]) {
  selectedLicenses.value = selection
}

function onLicenseRowClick(row: License) {
  router.push({ name: 'LicenseDetail', params: { code: row.code } })
}

// Version upload
function showUploadDialog() {
  uploadForm.version = ''
  uploadForm.file = null
  uploadProgress.value = 0
  uploadDialogVisible.value = true
  void nextTick(() => uploadRef.value?.clearFiles())
}

function onFileChange(file: UploadFile) {
  const raw = file.raw
  if (!raw) return
  if (!raw.name.toLowerCase().endsWith('.jar')) {
    ElMessage.warning('请选择 .jar 文件')
    uploadRef.value?.clearFiles()
    uploadForm.file = null
    return
  }
  if (raw.size > MAX_JAR_SIZE) {
    ElMessage.warning('JAR 文件不能超过 64 MiB')
    uploadRef.value?.clearFiles()
    uploadForm.file = null
    return
  }
  uploadForm.file = raw
}

function onFileRemove() {
  uploadForm.file = null
}

function onFileExceed() {
  ElMessage.warning('一次只能上传一个 JAR 文件，请先移除已选文件')
}

async function handleUpload() {
  if (!uploadForm.version.trim()) {
    ElMessage.warning('请输入版本号')
    return
  }
  if (!VERSION_PATTERN.test(uploadForm.version.trim())) {
    ElMessage.warning('版本号格式不符合要求')
    return
  }
  if (versions.value.some((item) => item.version === uploadForm.version.trim())) {
    ElMessage.warning('该版本号已存在')
    return
  }
  if (!uploadForm.file) {
    ElMessage.warning('请选择文件')
    return
  }
  uploadLoading.value = true
  uploadProgress.value = 0
  try {
    await programApi.uploadVersion(programId, uploadForm.version.trim(), uploadForm.file, (percent) => {
      uploadProgress.value = percent
    })
    ElMessage.success('上传成功')
    uploadDialogVisible.value = false
    loadVersions()
  } finally {
    uploadLoading.value = false
  }
}

async function handleDeleteVersion(versionId: number) {
  await programApi.deleteVersion(programId, versionId)
  ElMessage.success('删除成功')
  loadVersions()
}

// License operations
function onBindTypeChange(type: string) {
  switch (type) {
    case 'server_default':
      licenseForm.bindableIps = 1
      licenseForm.bindableHwids = 0
      break
    case 'single':
      licenseForm.bindableIps = 1
      licenseForm.bindableHwids = 1
      break
    case 'multi_ip':
      licenseForm.bindableIps = 3
      licenseForm.bindableHwids = 1
      break
    case 'limit_hwid':
      licenseForm.bindableIps = 0
      licenseForm.bindableHwids = 2
      break
    case 'unlimited':
      licenseForm.bindableIps = 0
      licenseForm.bindableHwids = 0
      break
    case 'cafe':
      licenseForm.bindableIps = 10
      licenseForm.bindableHwids = 0
      break
    case 'custom':
      licenseForm.bindableIps = 1
      licenseForm.bindableHwids = 1
      break
  }
}

function showLicenseDialog() {
  licenseForm.programIds = [programId]
  licenseForm.bindType = 'server_default'
  licenseForm.code = ''
  licenseForm.qq = ''
  licenseForm.bindableIps = 1
  licenseForm.bindableHwids = 0
  licenseForm.expirationDate = ''
  licenseForm.maxDailyAuth = 0
  licenseForm.notes = ''
  licenseDialogVisible.value = true
}

async function handleCreateLicense() {
  if (licenseForm.programIds.length === 0) {
    ElMessage.warning('请选择至少一个程序')
    return
  }
  const requestedCode = licenseForm.code.trim()
  const requestedQq = licenseForm.qq.trim()
  if (requestedCode && !isValidLicenseCode(requestedCode)) {
    ElMessage.warning('许可证只能包含字母、数字、点、下划线、加号和连字符，长度不超过256')
    return
  }
  if (requestedQq && !isValidQq(requestedQq)) {
    ElMessage.warning('QQ号必须是1–20位数字')
    return
  }
  licenseSubmitLoading.value = true
  try {
    const data: CreateLicenseRequest = {
      bindableIps: licenseForm.bindableIps,
      bindableHwids: licenseForm.bindableHwids,
      maxDailyAuth: licenseForm.maxDailyAuth,
    }
    if (requestedCode) data.code = requestedCode
    if (requestedQq) data.qq = requestedQq
    if (licenseForm.notes) data.notes = licenseForm.notes
    if (licenseForm.expirationDate) data.expirationDate = licenseForm.expirationDate
    if (authStore.isAdmin) {
      // 管理员端点会把许可证归属到程序所有者，普通端点会错误归属到当前管理员。
      const adminData: AdminCreateLicenseRequest = { ...data, programIds: licenseForm.programIds }
      const result = await adminCreateLicense(adminData)
      if (result.length === 0) ElMessage.warning('未创建许可证，请检查自定义许可证是否已存在')
      else ElMessage.success(`创建成功，共创建 ${result.length} 个许可证`)
    } else if (licenseForm.programIds.length === 1) {
      // Single program - use original endpoint
      await licenseApi.createLicense(licenseForm.programIds[0], data)
      ElMessage.success('创建成功')
    } else {
      // Multiple programs - use multi endpoint
      const multiData: MultiCreateLicenseRequest = { ...data, programIds: licenseForm.programIds }
      const result = await licenseApi.createLicenseMulti(multiData)
      ElMessage.success(`创建成功，共创建 ${Array.isArray(result) ? result.length : 1} 个许可证`)
    }
    licenseDialogVisible.value = false
    selectedLicenses.value = []
    loadLicenses()
  } finally {
    licenseSubmitLoading.value = false
  }
}

async function handleDeleteLicense(code: string) {
  await licenseApi.deleteLicense(code)
  ElMessage.success('删除成功')
  loadLicenses()
}

async function handleBatchBan() {
  const { value: reason } = await ElMessageBox.prompt('请输入封禁原因（可选）', '批量封禁', {
    confirmButtonText: '确认',
    cancelButtonText: '取消',
    inputPlaceholder: '封禁原因',
  }).catch(() => ({ value: null }))
  if (reason === null) return
  const codes = selectedLicenses.value.map((l) => l.code)
  await licenseApi.batchBan({ codes, reason: reason || undefined })
  ElMessage.success('批量封禁成功')
  loadLicenses()
}

async function handleBatchUnban() {
  const codes = selectedLicenses.value.map((l) => l.code)
  await licenseApi.batchUnban({ codes })
  ElMessage.success('批量解封成功')
  loadLicenses()
}

async function handleBatchDelete() {
  if (!await confirmAction(`确定删除选中的 ${selectedLicenses.value.length} 个许可证吗？`, '批量删除许可证')) return
  const codes = selectedLicenses.value.map((l) => l.code)
  await licenseApi.batchDelete({ codes })
  ElMessage.success('批量删除成功')
  loadLicenses()
}

onMounted(() => {
  if (!Number.isSafeInteger(programId) || programId <= 0) {
    void router.replace('/programs')
    return
  }
  void loadProgram()
})
</script>

<style scoped lang="scss">
.form-help {
  margin-top: 0.35rem;
  color: var(--color-text-muted);
  font-size: 0.75rem;
  line-height: 1.5;
}

.filter-bar :deep(.el-input),
.filter-bar :deep(.el-select) {
  width: 180px;
}
</style>
