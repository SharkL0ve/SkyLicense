<template>
  <div>
    <div class="stat-cards" v-loading="loading">
      <el-card class="stat-card" shadow="never" v-for="stat in statItems" :key="stat.label">
        <div class="stat-icon" :style="{ background: stat.iconBg }">
          <el-icon :size="28" :style="{ color: stat.iconColor }"><component :is="stat.icon" /></el-icon>
        </div>
        <div class="stat-content">
          <p class="stat-label">{{ stat.label }}</p>
          <h3 class="stat-value">{{ stat.value }}</h3>
          <p v-if="stat.meta" class="stat-meta">{{ stat.meta }}</p>
        </div>
      </el-card>
    </div>

    <el-card shadow="never">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span style="font-weight: 600; color: var(--color-text-primary);">快捷管理</span>
          <el-button type="primary" @click="handleReload" :loading="reloading" size="small">
            重载资源
          </el-button>
        </div>
      </template>
      <div style="display: flex; flex-wrap: wrap; gap: 12px;">
        <el-button @click="router.push('/admin/users')">用户管理</el-button>
        <el-button @click="router.push('/admin/programs')">程序管理</el-button>
        <el-button @click="router.push('/admin/licenses')">许可证管理</el-button>
        <el-button @click="router.push('/admin/operations')">操作日志</el-button>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getSystemStats, reloadResources } from '@/api/admin'
import type { SystemStats } from '@/types'
import { User, Box, Key, CircleCheck, CircleClose, Warning, Files, Document } from '@element-plus/icons-vue'

const router = useRouter()
const loading = ref(true)
const reloading = ref(false)
const stats = reactive<SystemStats>({
  userCount: 0,
  programCount: 0,
  licenseCount: 0,
  activeLicenses: 0,
  bannedLicenses: 0,
  banRecordCount: 0,
  authLogCount: 0,
  versionCount: 0,
  activeWebSessionCount: 0,
  activeClientSessionCount: 0,
  authRateLimitTrackedAddresses: 0,
  authRateLimitRejectedCount: 0,
  authRateLimitCapacityRejectedCount: 0,
  heartbeatRateLimitTrackedAddresses: 0,
  heartbeatRateLimitRejectedCount: 0,
  heartbeatRateLimitCapacityRejectedCount: 0,
})

const statItems = computed(() => [
  { label: '用户总数', value: stats.userCount, icon: User, iconBg: 'rgba(139, 92, 246, 0.1)', iconColor: '#8B5CF6' },
  { label: '程序总数', value: stats.programCount, icon: Box, iconBg: 'rgba(59, 130, 246, 0.1)', iconColor: '#3B82F6' },
  { label: '许可证总数', value: stats.licenseCount, icon: Key, iconBg: 'rgba(16, 185, 129, 0.1)', iconColor: '#10B981' },
  { label: '正常许可证', value: stats.activeLicenses, icon: CircleCheck, iconBg: 'rgba(34, 197, 94, 0.1)', iconColor: '#22C55E' },
  { label: '封禁许可证', value: stats.bannedLicenses, icon: CircleClose, iconBg: 'rgba(239, 68, 68, 0.1)', iconColor: '#EF4444' },
  { label: '封禁记录', value: stats.banRecordCount, icon: Warning, iconBg: 'rgba(245, 158, 11, 0.1)', iconColor: '#F59E0B' },
  { label: '版本总数', value: stats.versionCount, icon: Files, iconBg: 'rgba(6, 182, 212, 0.1)', iconColor: '#06B6D4' },
  { label: '验证记录', value: stats.authLogCount, icon: Document, iconBg: 'rgba(107, 114, 128, 0.1)', iconColor: '#6B7280' },
  { label: '活动后台会话', value: stats.activeWebSessionCount, icon: User, iconBg: 'rgba(14, 116, 144, 0.1)', iconColor: '#0E7490' },
  { label: '活动客户端会话', value: stats.activeClientSessionCount, icon: CircleCheck, iconBg: 'rgba(5, 150, 105, 0.1)', iconColor: '#059669' },
  {
    label: '认证限流拒绝',
    value: stats.authRateLimitRejectedCount,
    meta: `跟踪 ${stats.authRateLimitTrackedAddresses} · 容量拒绝 ${stats.authRateLimitCapacityRejectedCount}`,
    icon: Warning,
    iconBg: 'rgba(220, 38, 38, 0.1)',
    iconColor: '#DC2626',
  },
  {
    label: '心跳限流拒绝',
    value: stats.heartbeatRateLimitRejectedCount,
    meta: `跟踪 ${stats.heartbeatRateLimitTrackedAddresses} · 容量拒绝 ${stats.heartbeatRateLimitCapacityRejectedCount}`,
    icon: Warning,
    iconBg: 'rgba(234, 88, 12, 0.1)',
    iconColor: '#EA580C',
  },
])

async function loadStats() {
  loading.value = true
  try {
    const data = await getSystemStats()
    Object.assign(stats, data)
  } finally {
    loading.value = false
  }
}

async function handleReload() {
  const confirmed = await ElMessageBox.confirm(
    '资源重载会重新扫描服务端 JAR，在高峰期可能短暂影响验证请求。确定继续吗？',
    '确认重载资源',
    { type: 'warning', confirmButtonText: '继续重载' }
  ).then(() => true).catch(() => false)
  if (!confirmed) return
  reloading.value = true
  try {
    await reloadResources()
    ElMessage.success('资源重载成功')
    await loadStats()
  } finally {
    reloading.value = false
  }
}

onMounted(() => loadStats())
</script>

<style scoped>
.stat-meta {
  margin: 0.2rem 0 0;
  color: var(--color-text-muted);
  font-size: 0.72rem;
  line-height: 1.35;
}
</style>
