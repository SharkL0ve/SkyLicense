<template>
  <div class="login-container">
    <div class="login-bg">
      <div class="login-overlay"></div>
    </div>

    <div class="login-wrapper">
      <div class="login-card">
        <div class="login-side-image"></div>

        <div class="login-form-section">
          <div class="login-header">
            <h4 class="login-title">SkyLicense</h4>
            <p class="login-subtitle">许可证管理系统，请先登录账号</p>
          </div>

          <form class="login-form" @submit.prevent="handleSubmit">
            <div class="form-fields">
              <template v-if="step === 'credentials'">
                <div class="input-group">
                <input
                  id="username"
                  v-model="form.username"
                  type="text"
                  autocomplete="username"
                  maxlength="64"
                  required
                  :class="{ focused: focusedInput === 'username' || form.username }"
                  @focus="focusedInput = 'username'"
                  @blur="focusedInput = ''"
                />
                <label for="username" :class="{ active: focusedInput === 'username' || form.username, highlight: focusedInput === 'username' }">
                  用户名
                </label>
                </div>

                <div class="input-group">
                <input
                  id="password"
                  v-model="form.password"
                  type="password"
                  autocomplete="current-password"
                  maxlength="128"
                  required
                  :class="{ focused: focusedInput === 'password' || form.password }"
                  @focus="focusedInput = 'password'"
                  @blur="focusedInput = ''"
                />
                <label for="password" :class="{ active: focusedInput === 'password' || form.password, highlight: focusedInput === 'password' }">
                  密码
                </label>
                </div>
              </template>

              <template v-else>
                <div class="mfa-step-header">
                  <button type="button" class="back-link" :disabled="loading" @click="backToCredentials">
                    返回账号登录
                  </button>
                  <span class="mfa-account">{{ form.username }}</span>
                </div>
                <div class="input-group">
                  <input
                    id="factor"
                    v-model="factor"
                    type="text"
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    maxlength="64"
                    required
                    :class="{ focused: focusedInput === 'factor' || factor }"
                    @focus="focusedInput = 'factor'"
                    @blur="focusedInput = ''"
                  />
                  <label for="factor" :class="{ active: focusedInput === 'factor' || factor, highlight: focusedInput === 'factor' }">
                    验证码或恢复码
                  </label>
                </div>
                <p class="mfa-hint">输入验证器中的 6 位代码，或输入一条未使用的恢复码。</p>
              </template>
            </div>

            <button type="submit" class="login-btn" :disabled="loading">
              <span v-if="!loading">{{ step === 'credentials' ? '立即登录' : '验证并登录' }}</span>
              <span v-else>{{ step === 'credentials' ? '登录中...' : '验证中...' }}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const focusedInput = ref('')
const loading = ref(false)
const step = ref<'credentials' | 'mfa'>('credentials')
const challengeToken = ref('')
const factor = ref('')

const form = reactive({
  username: '',
  password: '',
})

async function handleSubmit() {
  if (loading.value) return
  if (step.value === 'credentials' && (!form.username || !form.password)) {
    ElMessage.warning('请输入用户名和密码')
    return
  }
  if (step.value === 'mfa' && (!challengeToken.value || !factor.value.trim())) {
    ElMessage.warning('请输入验证码或恢复码')
    return
  }

  loading.value = true
  try {
    if (step.value === 'credentials') {
      const result = await authStore.login({ username: form.username.trim(), password: form.password })
      if (result?.mfaRequired) {
        challengeToken.value = result.challengeToken || ''
        step.value = 'mfa'
        factor.value = ''
        ElMessage.info('请输入第二因素验证码')
        return
      }
    } else {
      await authStore.verifyMfa(challengeToken.value, factor.value.trim())
    }
    ElMessage.success('登录成功')
    const redirect = authStore.adminMfaRequired
      ? '/security'
      : typeof route.query.redirect === 'string' && route.query.redirect.startsWith('/')
      ? route.query.redirect
      : authStore.isAdmin ? '/admin' : '/dashboard'
    await router.replace(redirect)
  } finally {
    loading.value = false
  }
}

function backToCredentials() {
  step.value = 'credentials'
  challengeToken.value = ''
  factor.value = ''
  focusedInput.value = ''
}
</script>

<style scoped lang="scss">
.login-container {
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
}

.login-bg {
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, #0e7490 0%, #312e81 100%);
}

.login-overlay {
  position: absolute;
  inset: 0;
  background: rgba(0, 0, 0, 0.3);
  backdrop-filter: blur(4px);
}

.login-wrapper {
  position: relative;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  padding: 1rem;
}

.login-card {
  background: var(--color-bg-card);
  border-radius: 1rem;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
  width: 100%;
  max-width: 900px;
  overflow: hidden;
  display: flex;
  height: 520px;
}

.login-side-image {
  display: none;
  width: 50%;
  background: linear-gradient(135deg, #0e7490 0%, #4338ca 100%);
  position: relative;

  &::after {
    content: 'S';
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 120px;
    font-weight: 900;
    color: rgba(255, 255, 255, 0.15);
  }

  @media (min-width: 768px) {
    display: block;
  }
}

.login-form-section {
  width: 100%;
  padding: 2.5rem;
  display: flex;
  flex-direction: column;
  background-color: var(--color-bg-page);

  @media (min-width: 768px) {
    width: 50%;
    padding: 3rem;
  }
}

.login-header {
  margin-bottom: 2rem;

  .login-title {
    color: var(--color-primary);
    font-size: 28px;
    font-weight: 700;
    margin-bottom: 0.5rem;
  }

  .login-subtitle {
    color: var(--color-text-secondary);
    font-size: 14px;
  }
}

.login-form {
  display: flex;
  flex-direction: column;
  flex: 1;
}

.form-fields {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.mfa-step-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  min-height: 2rem;
}

.back-link {
  border: 0;
  background: transparent;
  color: var(--color-primary);
  padding: 0;
  cursor: pointer;
  font-size: 0.8125rem;
}

.back-link:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.mfa-account {
  color: var(--color-text-secondary);
  font-size: 0.8125rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mfa-hint {
  margin: -0.75rem 0 0;
  color: var(--color-text-muted);
  font-size: 0.75rem;
  line-height: 1.5;
}

.input-group {
  position: relative;

  input {
    width: 100%;
    border: 1px solid var(--color-border);
    border-radius: 0.5rem;
    padding: 1.25rem 1rem 0.5rem;
    outline: none;
    transition: all 0.3s;
    background: transparent;
    font-size: 14px;
    color: var(--color-text-primary);

    &.focused,
    &:focus {
      border-color: var(--color-primary);
      box-shadow: 0 0 0 2px var(--color-primary-ring);
    }
  }

  label {
    position: absolute;
    left: 1rem;
    top: 0.9rem;
    font-size: 14px;
    color: var(--color-text-muted);
    pointer-events: none;
    transition: all 0.3s;
    background: transparent;
    padding: 0 2px;

    &.active {
      top: 0.3rem;
      font-size: 11px;
    }

    &.highlight {
      color: var(--color-primary);
    }
  }
}

.login-btn {
  width: 100%;
  background-color: var(--color-primary);
  color: white;
  padding: 0.75rem;
  border-radius: 0.5rem;
  border: none;
  font-weight: 500;
  font-size: 15px;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 2px 8px var(--color-primary-ring);
  margin-top: 1.5rem;

  &:hover {
    background-color: var(--color-primary-hover);
    box-shadow: 0 4px 12px var(--color-primary-ring);
  }

  &:active {
    transform: scale(0.95);
  }

  &:disabled {
    opacity: 0.7;
    cursor: not-allowed;
  }
}
</style>
