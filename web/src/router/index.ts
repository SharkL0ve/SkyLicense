import { createRouter, createWebHistory } from 'vue-router'
import routes from './routes'
import { useAuthStore } from '@/stores/auth'
import { AUTH_EXPIRED_EVENT } from '@/api'

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

router.beforeEach(async (to) => {
  const authStore = useAuthStore()

  if (to.meta.requiresAuth === false) {
    if (authStore.user) {
      if (authStore.adminMfaRequired) return { path: '/security' }
      return { path: authStore.isAdmin ? '/admin' : '/dashboard' }
    }
    return true
  }

  if (!authStore.user) {
    try {
      await authStore.fetchUserInfo()
    } catch {
      authStore.reset()
      return { path: '/login', query: { redirect: to.fullPath } }
    }
  }

  if (to.meta.requiresAdmin && !authStore.isAdmin) {
    return { path: '/dashboard' }
  }

  if (authStore.adminMfaRequired && to.path !== '/security') {
    return { path: '/security', query: { required: 'mfa' } }
  }

  return true
})

router.afterEach((to) => {
  const title = typeof to.meta.title === 'string' ? to.meta.title : '管理控制台'
  document.title = `${title} · SkyLicense`
})

window.addEventListener(AUTH_EXPIRED_EVENT, () => {
  const redirect = router.currentRoute.value.fullPath
  useAuthStore().reset()
  if (router.currentRoute.value.path !== '/login') {
    void router.replace({ path: '/login', query: { redirect } })
  }
})

export default router
