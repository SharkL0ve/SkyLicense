import type { RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/LoginView.vue'),
    meta: { requiresAuth: false },
  },
  {
    path: '/',
    component: () => import('@/layouts/DefaultLayout.vue'),
    meta: { requiresAuth: true },
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/user/DashboardView.vue'),
        meta: { title: '仪表盘' },
      },
      {
        path: 'programs',
        name: 'Programs',
        component: () => import('@/views/user/ProgramsView.vue'),
        meta: { title: '程序管理' },
      },
      {
        path: 'programs/:id',
        name: 'ProgramDetail',
        component: () => import('@/views/user/ProgramDetailView.vue'),
        meta: { title: '程序详情' },
      },
      {
        path: 'licenses/:code',
        name: 'LicenseDetail',
        component: () => import('@/views/user/LicenseDetailView.vue'),
        meta: { title: '许可证详情' },
      },
      {
        path: 'bans',
        name: 'Bans',
        component: () => import('@/views/user/BansView.vue'),
        meta: { title: '封禁管理' },
      },
      {
        path: 'auth-logs',
        name: 'AuthLogs',
        component: () => import('@/views/user/AuthLogsView.vue'),
        meta: { title: '验证日志' },
      },
      {
        path: 'security',
        name: 'AccountSecurity',
        component: () => import('@/views/AccountSecurityView.vue'),
        meta: { title: '账户安全' },
      },
      // Admin routes
      {
        path: 'admin',
        name: 'AdminDashboard',
        component: () => import('@/views/admin/DashboardView.vue'),
        meta: { title: '系统概览', requiresAdmin: true },
      },
      {
        path: 'admin/users',
        name: 'AdminUsers',
        component: () => import('@/views/admin/UsersView.vue'),
        meta: { title: '用户管理', requiresAdmin: true },
      },
      {
        path: 'admin/users/:id',
        name: 'AdminUserDetail',
        component: () => import('@/views/admin/UserDetailView.vue'),
        meta: { title: '用户详情', requiresAdmin: true },
      },
      {
        path: 'admin/programs',
        name: 'AdminPrograms',
        component: () => import('@/views/admin/ProgramsView.vue'),
        meta: { title: '程序管理', requiresAdmin: true },
      },
      {
        path: 'admin/licenses',
        name: 'AdminLicenses',
        component: () => import('@/views/admin/LicensesView.vue'),
        meta: { title: '许可证管理', requiresAdmin: true },
      },
      {
        path: 'admin/operations',
        name: 'AdminOperations',
        component: () => import('@/views/admin/OperationsView.vue'),
        meta: { title: '操作日志', requiresAdmin: true },
      },
      {
        path: 'admin/auth-logs',
        name: 'AdminAuthLogs',
        component: () => import('@/views/admin/AuthLogsView.vue'),
        meta: { title: '验证日志', requiresAdmin: true },
      },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/login',
  },
]

export default routes
