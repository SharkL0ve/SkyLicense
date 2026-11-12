<template>
  <div class="dashboard-container">
    <!-- Mobile Sidebar Overlay -->
    <div v-if="sidebarOpen" class="sidebar-overlay" aria-hidden="true" @click="sidebarOpen = false"></div>

    <!-- Sidebar -->
    <aside class="sidebar" :class="{ open: sidebarOpen }">
      <div class="sidebar-logo">
        <span class="logo-text">SkyLicense</span>
      </div>

      <nav class="sidebar-nav">
        <template v-if="!authStore.adminMfaRequired">
          <!-- User menu items -->
          <router-link to="/dashboard" class="nav-item" :class="{ active: isActive('/dashboard') }" @click="sidebarOpen = false">
            仪表盘
          </router-link>

        <div class="nav-category">
          <h3 class="nav-category-title">内容管理</h3>
          <router-link to="/programs" class="nav-item" :class="{ active: isActive('/programs') }" @click="sidebarOpen = false">
            程序管理
          </router-link>
          <router-link to="/bans" class="nav-item" :class="{ active: isActive('/bans') }" @click="sidebarOpen = false">
            封禁管理
          </router-link>
          <router-link to="/auth-logs" class="nav-item" :class="{ active: isActive('/auth-logs') }" @click="sidebarOpen = false">
            验证日志
          </router-link>
        </div>

          <template v-if="authStore.isAdmin">
          <div class="nav-category">
            <h3 class="nav-category-title">系统管理</h3>
            <router-link to="/admin" class="nav-item" :class="{ active: route.path === '/admin' }" @click="sidebarOpen = false">
              系统概览
            </router-link>
            <router-link to="/admin/users" class="nav-item" :class="{ active: isActive('/admin/users') }" @click="sidebarOpen = false">
              用户管理
            </router-link>
            <router-link to="/admin/programs" class="nav-item" :class="{ active: route.path === '/admin/programs' }" @click="sidebarOpen = false">
              程序管理
            </router-link>
            <router-link to="/admin/licenses" class="nav-item" :class="{ active: route.path === '/admin/licenses' }" @click="sidebarOpen = false">
              许可证管理
            </router-link>
            <router-link to="/admin/operations" class="nav-item" :class="{ active: route.path === '/admin/operations' }" @click="sidebarOpen = false">
              操作日志
            </router-link>
            <router-link to="/admin/auth-logs" class="nav-item" :class="{ active: route.path === '/admin/auth-logs' }" @click="sidebarOpen = false">
              验证日志
            </router-link>
          </div>
          </template>
        </template>
      </nav>

      <!-- User section at bottom -->
      <div class="sidebar-footer">
        <div class="user-menu-popup" :class="{ active: showUserMenu }">
          <div class="menu-item" @click="openAccountSecurity">
            账户安全
          </div>
          <div class="menu-item" @click="passwordDialogVisible = true; showUserMenu = false">
            修改密码
          </div>
          <div class="menu-item danger" @click="handleLogout">
            退出登录
          </div>
        </div>
        <button
          type="button"
          class="user-info-card"
          :aria-expanded="showUserMenu"
          aria-label="打开账户菜单"
          @click="showUserMenu = !showUserMenu"
        >
          <div class="user-avatar">{{ authStore.user?.username?.charAt(0)?.toUpperCase() }}</div>
          <div class="user-details">
            <p class="user-name">{{ authStore.user?.username }}</p>
            <p class="user-role">{{ authStore.isAdmin ? '管理员' : '普通用户' }}</p>
          </div>
        </button>
      </div>
    </aside>

    <!-- Main content -->
    <div class="main-wrapper">
      <header class="main-header">
        <button class="menu-toggle" aria-label="打开导航菜单" @click="sidebarOpen = true">
          <svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <h2 class="header-title">{{ currentTitle }}</h2>
        <button class="theme-toggle" @click="handleToggleTheme" :title="isDark ? '切换亮色模式' : '切换暗色模式'">
          <svg v-if="isDark" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
          </svg>
          <svg v-else width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
          </svg>
        </button>
      </header>

      <main class="main-content">
        <div class="content-container">
          <router-view v-slot="{ Component }">
            <transition name="fade" mode="out-in">
              <component :is="Component" />
            </transition>
          </router-view>
        </div>
      </main>
    </div>
  </div>

  <!-- Change Password Dialog -->
  <el-dialog
    v-model="passwordDialogVisible"
    title="修改密码"
    width="420px"
    :append-to-body="true"
    destroy-on-close
    @closed="resetPasswordForm"
  >
    <el-form ref="pwdFormRef" :model="pwdForm" :rules="pwdRules" label-width="80px">
      <el-form-item label="旧密码" prop="oldPassword">
        <el-input v-model="pwdForm.oldPassword" type="password" autocomplete="current-password" maxlength="128" show-password />
      </el-form-item>
      <el-form-item label="新密码" prop="newPassword">
        <el-input v-model="pwdForm.newPassword" type="password" autocomplete="new-password" maxlength="128" show-password />
        <div class="form-hint">{{ PASSWORD_HINT }}</div>
      </el-form-item>
      <el-form-item label="确认密码" prop="confirmPassword">
        <el-input v-model="pwdForm.confirmPassword" type="password" autocomplete="new-password" maxlength="128" show-password />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="passwordDialogVisible = false">取消</el-button>
      <el-button type="primary" :loading="pwdLoading" @click="handleChangePassword">确认</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { changePassword } from '@/api/auth'
import { toggleTheme, getTheme } from '@/utils/theme'
import { PASSWORD_HINT, passwordRule } from '@/utils/validation'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const sidebarOpen = ref(false)
const showUserMenu = ref(false)
const isDark = ref(getTheme() === 'dark')
const currentTitle = computed(() => (route.meta.title as string) || '仪表盘')

function handleToggleTheme() {
  const newTheme = toggleTheme()
  isDark.value = newTheme === 'dark'
}

function openAccountSecurity() {
  showUserMenu.value = false
  void router.push('/security')
}

function isActive(path: string): boolean {
  return route.path === path || route.path.startsWith(path + '/')
}

async function handleLogout() {
  showUserMenu.value = false
  try {
    await authStore.logout()
  } catch {
    // 请求层已提示错误；本地会话仍需退出。
  } finally {
    await router.replace('/login')
  }
}

// Password dialog
const passwordDialogVisible = ref(false)
const pwdLoading = ref(false)
const pwdFormRef = ref<FormInstance>()
const pwdForm = reactive({ oldPassword: '', newPassword: '', confirmPassword: '' })
const pwdRules: FormRules = {
  oldPassword: [
    { required: true, message: '请输入旧密码', trigger: 'blur' },
    { max: 128, message: '旧密码不能超过 128 位', trigger: 'blur' },
  ],
  newPassword: [
    passwordRule({ required: true }),
    {
      trigger: 'blur',
      validator: (_rule, value: unknown, callback) => {
        if (value === pwdForm.oldPassword) callback(new Error('新密码不能与旧密码相同'))
        else callback()
      },
    },
  ],
  confirmPassword: [{
    trigger: 'blur',
    validator: (_rule, value: unknown, callback) => {
      if (value !== pwdForm.newPassword) callback(new Error('两次输入的新密码不一致'))
      else callback()
    },
  }],
}

function resetPasswordForm() {
  pwdForm.oldPassword = ''
  pwdForm.newPassword = ''
  pwdForm.confirmPassword = ''
  pwdFormRef.value?.clearValidate()
}

async function handleChangePassword() {
  const valid = await pwdFormRef.value?.validate().catch(() => false)
  if (!valid) return
  pwdLoading.value = true
  try {
    await changePassword({ oldPassword: pwdForm.oldPassword, newPassword: pwdForm.newPassword })
    ElMessage.success('密码修改成功，请重新登录')
    passwordDialogVisible.value = false
    authStore.reset()
    await router.replace('/login')
  } finally {
    pwdLoading.value = false
  }
}
</script>

<style scoped lang="scss">
.dashboard-container {
  display: flex;
  height: 100vh;
  background: var(--color-bg-page);
  position: relative;
  overflow: hidden;
}

.sidebar-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  z-index: 20;
  transition: opacity 0.3s;

  @media (min-width: 768px) {
    display: none;
  }
}

.sidebar {
  width: 256px;
  background: var(--color-bg-card);
  box-shadow: var(--shadow-lg);
  display: flex;
  flex-direction: column;
  z-index: 30;
  transition: transform 0.3s;
  position: absolute;
  inset: 0 auto 0 0;
  transform: translateX(-100%);

  @media (min-width: 768px) {
    position: relative;
    transform: translateX(0);
  }

  &.open {
    transform: translateX(0);
  }
}

.sidebar-logo {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-bottom: 1px solid var(--color-border);

  .logo-text {
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--color-primary);
  }
}

.sidebar-nav {
  flex: 1;
  overflow-y: auto;
  padding: 1.5rem 0.75rem;
}

.nav-item {
  display: flex;
  align-items: center;
  padding: 0.75rem 1rem;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--color-text-secondary);
  border-radius: var(--radius-lg);
  transition: all 0.2s;
  text-decoration: none;
  margin-bottom: 2px;

  &:hover {
    background: var(--color-bg-hover);
    color: var(--color-text-primary);
  }

  &.active {
    background: var(--color-primary-light);
    color: var(--color-primary);
  }
}

.nav-category {
  margin-top: 1.5rem;

  &:first-child {
    margin-top: 0.5rem;
  }
}

.nav-category-title {
  padding: 0 1rem;
  font-size: 0.7rem;
  font-weight: 700;
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 0.5rem;
  margin-left: 0.25rem;
}

.sidebar-footer {
  padding: 1rem;
  border-top: 1px solid var(--color-border);
  position: relative;
}

.user-menu-popup {
  position: absolute;
  bottom: 100%;
  left: 0.5rem;
  right: 0.5rem;
  background: var(--color-bg-card);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  border: 1px solid var(--color-border);
  margin-bottom: 0.5rem;
  padding: 0.5rem;
  display: none;

  &.active {
    display: block;
    animation: slideUp 0.2s ease-out;
  }

  .menu-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem 1rem;
    border-radius: var(--radius-sm);
    color: var(--color-text-secondary);
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;

    &:hover {
      background: var(--color-bg-hover);
    }

    &.danger {
      color: var(--color-danger);

      &:hover {
        background: var(--color-danger-light);
      }
    }
  }
}

@keyframes slideUp {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

.user-info-card {
  width: 100%;
  border: 0;
  background: transparent;
  text-align: left;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem;
  border-radius: var(--radius-lg);
  cursor: pointer;
  transition: background 0.2s;

  &:hover {
    background: var(--color-bg-hover);
  }
}

.form-hint {
  margin-top: 0.35rem;
  color: var(--color-text-muted);
  font-size: 0.75rem;
  line-height: 1.5;
}

.user-avatar {
  width: 2.25rem;
  height: 2.25rem;
  border-radius: 50%;
  background: var(--color-primary-light);
  color: var(--color-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 0.875rem;
  flex-shrink: 0;
}

.user-details {
  flex: 1;
  min-width: 0;

  .user-name {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--color-text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .user-role {
    font-size: 0.75rem;
    color: var(--color-text-muted);
  }
}

.main-wrapper {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: var(--color-bg-page);
}

.main-header {
  height: 64px;
  background: var(--color-bg-card);
  box-shadow: var(--shadow-sm);
  display: flex;
  align-items: center;
  padding: 0 1rem;
  position: sticky;
  top: 0;
  z-index: 10;

  @media (min-width: 768px) {
    padding: 0 2rem;
  }
}

.menu-toggle {
  display: flex;
  margin-right: 1rem;
  color: var(--color-text-secondary);
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.25rem;

  &:hover {
    color: var(--color-text-primary);
  }

  @media (min-width: 768px) {
    display: none;
  }
}

.header-title {
  font-size: 1.125rem;
  font-weight: 700;
  color: var(--color-text-primary);
  flex: 1;
}

.theme-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 2.25rem;
  height: 2.25rem;
  border-radius: 0.5rem;
  border: none;
  background: transparent;
  color: var(--color-text-secondary);
  cursor: pointer;
  transition: all 0.2s;

  &:hover {
    background: var(--color-bg-hover);
    color: var(--color-primary);
  }
}

.main-content {
  flex: 1;
  overflow: auto;
  padding: 1rem;

  @media (min-width: 768px) {
    padding: 2rem;
  }
}

.content-container {
  max-width: 1280px;
  margin: 0 auto;
}
</style>
