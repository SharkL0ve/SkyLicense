<template>
  <div>
    <div class="stat-cards">
      <el-card class="stat-card" shadow="never">
        <div class="stat-icon" style="background: rgba(59, 130, 246, 0.1);">
          <el-icon :size="28" style="color: #3B82F6;"><Box /></el-icon>
        </div>
        <div class="stat-content">
          <p class="stat-label">已创建程序</p>
          <h3 class="stat-value">{{ programCount }}</h3>
        </div>
      </el-card>
      <el-card class="stat-card" shadow="never">
        <div class="stat-icon" style="background: rgba(16, 185, 129, 0.1);">
          <el-icon :size="28" style="color: #10B981;"><Folder /></el-icon>
        </div>
        <div class="stat-content">
          <p class="stat-label">程序配额</p>
          <h3 class="stat-value">{{ authStore.user?.maxPrograms ?? 0 }}</h3>
        </div>
      </el-card>
      <el-card class="stat-card" shadow="never">
        <div class="stat-icon" style="background: rgba(245, 158, 11, 0.1);">
          <el-icon :size="28" style="color: #f59e0b;"><CirclePlus /></el-icon>
        </div>
        <div class="stat-content">
          <p class="stat-label">剩余可创建</p>
          <h3 class="stat-value">{{ remainingPrograms }}</h3>
        </div>
      </el-card>
    </div>

    <el-card shadow="never">
      <template #header>
        <span style="font-weight: 600; color: var(--color-text-primary);">快捷操作</span>
      </template>
      <div style="display: flex; flex-wrap: wrap; gap: 12px;">
        <el-button type="primary" @click="router.push('/programs')">程序管理</el-button>
        <el-button @click="router.push('/bans')">封禁管理</el-button>
        <el-button @click="router.push('/auth-logs')">验证日志</el-button>
        <template v-if="authStore.isAdmin">
          <el-button type="danger" @click="router.push('/admin')">系统管理</el-button>
        </template>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { getPrograms } from '@/api/programs'
import { Box, Folder, CirclePlus } from '@element-plus/icons-vue'

const router = useRouter()
const authStore = useAuthStore()
const programCount = ref(0)
const remainingPrograms = computed(() => Math.max(0, (authStore.user?.maxPrograms ?? 0) - programCount.value))

onMounted(async () => {
  try {
    const data = await getPrograms({ page: 1, pageSize: 1 })
    programCount.value = data.total
  } catch {
    // ignore
  }
})
</script>
