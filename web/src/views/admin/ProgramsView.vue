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
    </div>

    <div class="list-table-card">
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>程序名称</th>
              <th>用户ID</th>
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
              <td>{{ program.userId }}</td>
              <td class="td-time" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ program.description || '-' }}</td>
              <td>
                <span class="status-dot" :class="program.status === 1 ? 'dot-active' : 'dot-inactive'"></span>
                {{ program.status === 1 ? '正常' : '禁用' }}
              </td>
              <td class="td-time">{{ program.createTime || '-' }}</td>
              <td class="td-actions" @click.stop>
                <div class="action-buttons">
                  <button class="action-btn" :class="program.status === 1 ? 'action-ban' : 'action-unban'" :title="program.status === 1 ? '禁用' : '启用'" @click="handleToggleStatus(program)">
                    <svg v-if="program.status === 1" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                    <svg v-else width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
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
          <p>未找到程序</p>
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
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useTable } from '@/composables/useTable'
import { getAdminPrograms } from '@/api/admin'
import { toggleProgramStatus } from '@/api/programs'
import type { Program } from '@/types'
import AppPagination from '@/components/AppPagination.vue'

const router = useRouter()
const searchQuery = ref('')

const { tableData, total, loading, pagination, load, onPageChange, onSizeChange } = useTable(
  (params) => getAdminPrograms(params)
)

const displayedPrograms = computed(() => {
  const keyword = searchQuery.value.trim().toLocaleLowerCase()
  if (!keyword) return tableData.value
  return tableData.value.filter((program) =>
    program.name.toLocaleLowerCase().includes(keyword)
      || program.description?.toLocaleLowerCase().includes(keyword)
      || String(program.userId).includes(keyword)
  )
})

async function handleToggleStatus(program: Program) {
  const newStatus = program.status === 1 ? 0 : 1
  await toggleProgramStatus(program.id, newStatus)
  ElMessage.success(newStatus === 1 ? '已启用' : '已禁用')
  load()
}

onMounted(() => load())
</script>

<style scoped lang="scss">
@use '@/styles/list-view.scss';
</style>
