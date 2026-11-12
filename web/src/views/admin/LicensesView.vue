<template>
  <div class="list-view">
    <div class="list-toolbar">
      <div class="toolbar-left">
        <div class="search-box">
          <svg class="search-icon" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input v-model="searchQuery" placeholder="筛选当前页许可证" aria-label="筛选当前页许可证" />
        </div>
      </div>
      <div class="toolbar-right">
        <button class="btn-primary" :disabled="allPrograms.length === 0" @click="showCreateDialog">
          <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          创建许可证
        </button>
      </div>
    </div>

    <div class="list-table-card">
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>许可证</th>
              <th>程序ID</th>
              <th>用户ID</th>
              <th>QQ</th>
              <th>状态</th>
              <th>创建时间</th>
              <th class="th-actions">操作</th>
            </tr>
          </thead>
          <tbody v-if="displayedLicenses.length > 0">
            <tr v-for="license in displayedLicenses" :key="license.id" class="table-row clickable-row" tabindex="0" @click="openLicense(license.code)" @keyup.enter="openLicense(license.code)">
              <td>
                <span class="code-text">{{ license.code }}</span>
              </td>
              <td>{{ license.programId }}</td>
              <td>{{ license.userId }}</td>
              <td>{{ license.qq || '-' }}</td>
              <td>
                <span class="status-dot" :class="license.status === 1 ? 'dot-active' : 'dot-inactive'"></span>
                {{ license.status === 1 ? '正常' : '封禁' }}
              </td>
              <td class="td-time">{{ license.createTime || '-' }}</td>
              <td class="td-actions" @click.stop>
                <div class="action-buttons">
                  <button class="action-btn" :class="license.status === 1 ? 'action-ban' : 'action-unban'" :title="license.status === 1 ? '封禁' : '解封'" @click="handleToggleBan(license)">
                    <svg v-if="license.status === 1" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                    <svg v-else width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>

        <div v-if="displayedLicenses.length === 0 && !loading" class="empty-state">
          <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="opacity: 0.4;">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
          </svg>
          <p>未找到许可证</p>
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

    <!-- Create License Dialog -->
    <el-dialog v-model="dialogVisible" title="创建许可证（管理员）" width="520px" :append-to-body="true">
      <el-form :model="form" label-width="110px">
        <el-form-item label="目标程序">
          <div style="width: 100%;">
            <el-checkbox v-model="form.allPrograms" @change="onAllProgramsChange">所有程序</el-checkbox>
            <div v-if="!form.allPrograms" style="margin-top: 8px;">
              <el-select
                v-model="form.programIds"
                multiple
                filterable
                placeholder="选择程序（可多选、可搜索）"
                style="width: 100%;"
              >
                <el-option
                  v-for="p in allPrograms"
                  :key="p.id"
                  :label="`${p.name} (ID: ${p.id})`"
                  :value="p.id"
                />
              </el-select>
            </div>
          </div>
        </el-form-item>
        <el-form-item label="许可证">
          <el-input v-model="form.code" maxlength="256" placeholder="留空自动生成UUID（多程序时自动追加后缀）" />
        </el-form-item>
        <el-form-item label="QQ号">
          <el-input v-model="form.qq" placeholder="关联QQ号（可选，1–20位数字）" maxlength="20" show-word-limit />
        </el-form-item>
        <el-form-item label="绑定限制">
          <el-select v-model="form.bindType" style="width: 100%;" @change="onBindTypeChange">
            <el-option label="服务端默认 — 1 个 IP，不限制机器码" value="server_default" />
            <el-option label="单机授权 — 一台机器一个IP" value="single" />
            <el-option label="多IP单机 — 一台机器，允许IP变化" value="multi_ip" />
            <el-option label="不限IP限机器 — 不管IP，限制机器数" value="limit_hwid" />
            <el-option label="完全不限 — 不检查IP和机器码" value="unlimited" />
            <el-option label="网吧授权 — 多IP，不限机器码" value="cafe" />
            <el-option label="自定义" value="custom" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.bindType === 'multi_ip' || form.bindType === 'cafe' || form.bindType === 'custom'" label="可绑定IP数">
          <el-input-number v-model="form.bindableIps" :min="0" />
          <span style="margin-left: 8px; color: #9ca3af; font-size: 12px;">0 = 不限制</span>
        </el-form-item>
        <el-form-item v-if="form.bindType === 'limit_hwid' || form.bindType === 'custom'" label="可绑定机器码">
          <el-input-number v-model="form.bindableHwids" :min="0" />
          <span style="margin-left: 8px; color: #9ca3af; font-size: 12px;">0 = 不限制</span>
        </el-form-item>
        <el-form-item label="到期时间">
          <el-date-picker
            v-model="form.expirationDate"
            type="datetime"
            format="YYYY-MM-DD HH:mm"
            value-format="YYYY-MM-DD-HH:mm"
            placeholder="留空表示永久有效"
            style="width: 100%;"
          />
        </el-form-item>
        <el-form-item label="每日验证上限">
          <el-input-number v-model="form.maxDailyAuth" :min="0" :max="1000000" />
          <span style="margin-left: 8px; color: #9ca3af; font-size: 12px;">0 = 不限制</span>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="form.notes" type="textarea" :rows="2" maxlength="2048" show-word-limit />
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
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useTable } from '@/composables/useTable'
import { getAdminLicenses, getAdminPrograms, adminCreateLicense } from '@/api/admin'
import { banLicense, unbanLicense } from '@/api/licenses'
import type { License, Program, AdminCreateLicenseRequest } from '@/types'
import AppPagination from '@/components/AppPagination.vue'
import { fetchAllPages } from '@/utils/pagination'
import { isValidLicenseCode, isValidQq } from '@/utils/validation'

const router = useRouter()
const searchQuery = ref('')
const allPrograms = ref<Program[]>([])

const { tableData, total, loading, pagination, load, onPageChange, onSizeChange } = useTable(
  (params) => getAdminLicenses(params)
)

const displayedLicenses = computed(() => {
  const keyword = searchQuery.value.trim().toLocaleLowerCase()
  if (!keyword) return tableData.value
  return tableData.value.filter((license) =>
    license.code.toLocaleLowerCase().includes(keyword)
      || license.qq?.toLocaleLowerCase().includes(keyword)
      || String(license.programId).includes(keyword)
      || String(license.userId).includes(keyword)
  )
})

function openLicense(code: string) {
  void router.push({ name: 'LicenseDetail', params: { code } })
}

const dialogVisible = ref(false)
const submitLoading = ref(false)
const form = reactive({
  allPrograms: false,
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

function onBindTypeChange(type: string) {
  switch (type) {
    case 'server_default':
      form.bindableIps = 1; form.bindableHwids = 0; break
    case 'single':
      form.bindableIps = 1; form.bindableHwids = 1; break
    case 'multi_ip':
      form.bindableIps = 3; form.bindableHwids = 1; break
    case 'limit_hwid':
      form.bindableIps = 0; form.bindableHwids = 2; break
    case 'unlimited':
      form.bindableIps = 0; form.bindableHwids = 0; break
    case 'cafe':
      form.bindableIps = 10; form.bindableHwids = 0; break
    case 'custom':
      form.bindableIps = 1; form.bindableHwids = 1; break
  }
}

function onAllProgramsChange() {
  if (form.allPrograms) form.programIds = []
}

function showCreateDialog() {
  form.allPrograms = false
  form.programIds = []
  form.bindType = 'server_default'
  form.code = ''
  form.qq = ''
  form.bindableIps = 1
  form.bindableHwids = 0
  form.expirationDate = ''
  form.maxDailyAuth = 0
  form.notes = ''
  dialogVisible.value = true
}

async function handleCreate() {
  if (!form.allPrograms && form.programIds.length === 0) {
    ElMessage.warning('请选择程序或勾选所有程序')
    return
  }
  if (form.allPrograms && allPrograms.value.length === 0) {
    ElMessage.warning('当前没有可授权的程序')
    return
  }
  const requestedCode = form.code.trim()
  const requestedQq = form.qq.trim()
  if (requestedCode && !isValidLicenseCode(requestedCode)) {
    ElMessage.warning('许可证格式无效，长度最多256且只能使用安全字符')
    return
  }
  if (requestedQq && !isValidQq(requestedQq)) {
    ElMessage.warning('QQ号必须是1–20位数字')
    return
  }
  submitLoading.value = true
  try {
    const reqData: AdminCreateLicenseRequest = {
      programIds: form.allPrograms ? [] : form.programIds,
      bindableIps: form.bindableIps,
      bindableHwids: form.bindableHwids,
      maxDailyAuth: form.maxDailyAuth,
    }
    if (form.allPrograms) {
      reqData.allPrograms = true
    }
    if (requestedCode) reqData.code = requestedCode
    if (requestedQq) reqData.qq = requestedQq
    if (form.notes) reqData.notes = form.notes
    if (form.expirationDate) reqData.expirationDate = form.expirationDate
    const result = await adminCreateLicense(reqData)
    if (result.length === 0) ElMessage.warning('未创建许可证，请检查自定义许可证是否已存在')
    else ElMessage.success(`创建成功，共创建 ${result.length} 个许可证`)
    dialogVisible.value = false
    load()
  } finally {
    submitLoading.value = false
  }
}

async function handleToggleBan(license: License) {
  if (license.status === 1) {
    await banLicense(license.code, '管理员封禁')
    ElMessage.success('已封禁')
  } else {
    await unbanLicense(license.code)
    ElMessage.success('已解封')
  }
  load()
}

onMounted(async () => {
  void load()
  try {
    allPrograms.value = await fetchAllPages(getAdminPrograms)
  } catch {
    // ignore
  }
})
</script>

<style scoped lang="scss">
@use '@/styles/list-view.scss';

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
</style>
