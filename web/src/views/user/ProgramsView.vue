<template>
  <div class="list-view">
    <div class="list-toolbar">
      <div class="toolbar-left">
        <div class="search-box">
          <svg class="search-icon" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input v-model="searchQuery" placeholder="筛选当前页程序" aria-label="筛选当前页程序" />
        </div>
      </div>
      <div class="toolbar-right">
        <button class="btn-primary" :disabled="programLimitReached" @click="showCreateDialog">
          <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          创建程序
        </button>
      </div>
    </div>

    <div class="list-table-card">
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>程序名称</th>
              <th>描述</th>
              <th>状态</th>
              <th>创建时间</th>
              <th class="th-actions">操作</th>
            </tr>
          </thead>
          <tbody v-if="displayedPrograms.length > 0">
            <tr v-for="program in displayedPrograms" :key="program.id" class="table-row clickable-row" tabindex="0" @click="router.push(`/programs/${program.id}`)" @keyup.enter="router.push(`/programs/${program.id}`)">
              <td>{{ program.id }}</td>
              <td><span style="font-weight: 500;">{{ program.name }}</span></td>
              <td class="td-time" style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ program.description || '-' }}</td>
              <td>
                <span class="status-dot" :class="program.status === 1 ? 'dot-active' : 'dot-inactive'"></span>
                {{ program.status === 1 ? '正常' : '禁用' }}
              </td>
              <td class="td-time">{{ program.createTime || '-' }}</td>
              <td class="td-actions" @click.stop>
                <div class="action-buttons">
                  <button class="action-btn action-edit" title="编辑" @click="showEditDialog(program)">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                  </button>
                  <button class="action-btn" :class="program.status === 1 ? 'action-ban' : 'action-unban'" :title="program.status === 1 ? '禁用' : '启用'" @click="handleToggleStatus(program)">
                    <svg v-if="program.status === 1" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                    <svg v-else width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                  </button>
                  <button class="action-btn action-delete" title="删除" @click="handleDelete(program)">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>

        <div v-if="displayedPrograms.length === 0 && !loading" class="empty-state">
          <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="opacity: 0.4;">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/>
          </svg>
          <p>暂无程序，点击上方按钮创建</p>
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

    <!-- Create/Edit Dialog -->
    <el-dialog v-model="dialogVisible" :title="editingProgram ? '编辑程序' : '创建程序'" width="450px" :append-to-body="true">
      <el-form ref="formRef" :model="form" :rules="formRules" label-width="80px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="程序名称" maxlength="64" show-word-limit />
          <div class="form-help">1–64 位，可使用字母、数字、点、下划线、加号和连字符。</div>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" type="textarea" :rows="3" placeholder="程序描述（可选）" maxlength="2048" show-word-limit />
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
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { useTable } from '@/composables/useTable'
import * as programApi from '@/api/programs'
import type { Program } from '@/types'
import AppPagination from '@/components/AppPagination.vue'
import { useAuthStore } from '@/stores/auth'
import { confirmAction } from '@/utils/confirm'
import { PROGRAM_NAME_PATTERN } from '@/utils/validation'

const router = useRouter()
const authStore = useAuthStore()
const searchQuery = ref('')

const { tableData, total, loading, pagination, load, onPageChange, onSizeChange } = useTable(
  (params) => programApi.getPrograms(params)
)

const displayedPrograms = computed(() => {
  const keyword = searchQuery.value.trim().toLocaleLowerCase()
  if (!keyword) return tableData.value
  return tableData.value.filter((program) =>
    program.name.toLocaleLowerCase().includes(keyword)
      || program.description?.toLocaleLowerCase().includes(keyword)
  )
})
const programLimitReached = computed(() =>
  !authStore.isAdmin && total.value >= (authStore.user?.maxPrograms ?? 0)
)

const dialogVisible = ref(false)
const submitLoading = ref(false)
const editingProgram = ref<Program | null>(null)
const formRef = ref<FormInstance>()
const form = reactive({ name: '', description: '' })
const formRules: FormRules = {
  name: [
    { required: true, message: '请输入程序名称', trigger: 'blur' },
    {
      pattern: PROGRAM_NAME_PATTERN,
      message: '名称只能包含字母、数字、点、下划线、加号和连字符',
      trigger: 'blur',
    },
  ],
}

function showCreateDialog() {
  if (programLimitReached.value) {
    ElMessage.warning('已达到可创建程序数量上限')
    return
  }
  editingProgram.value = null
  form.name = ''
  form.description = ''
  dialogVisible.value = true
}

function showEditDialog(program: Program) {
  editingProgram.value = program
  form.name = program.name
  form.description = program.description || ''
  dialogVisible.value = true
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  if (!form.name.trim()) {
    ElMessage.warning('程序名称不能只包含空格')
    return
  }
  submitLoading.value = true
  try {
    if (editingProgram.value) {
      await programApi.updateProgram(editingProgram.value.id, { name: form.name.trim(), description: form.description.trim() })
      ElMessage.success('修改成功')
    } else {
      await programApi.createProgram({ name: form.name.trim(), description: form.description.trim() })
      ElMessage.success('创建成功')
    }
    dialogVisible.value = false
    load()
  } finally {
    submitLoading.value = false
  }
}

async function handleToggleStatus(program: Program) {
  const newStatus = program.status === 1 ? 0 : 1
  await programApi.toggleProgramStatus(program.id, newStatus)
  ElMessage.success(newStatus === 1 ? '已启用' : '已禁用')
  load()
}

async function handleDelete(program: Program) {
  if (!await confirmAction(`确定删除程序“${program.name}”吗？相关版本与许可证可能同时失效。`, '删除程序')) return
  await programApi.deleteProgram(program.id)
  ElMessage.success('删除成功')
  load()
}

onMounted(() => load())
</script>

<style scoped lang="scss">
@use '@/styles/list-view.scss';
</style>
