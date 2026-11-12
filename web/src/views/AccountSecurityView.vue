<template>
  <div class="security-page">
    <header class="page-header">
      <div>
        <h1>账户安全</h1>
        <p>{{ status?.enabled ? '多因素认证已启用' : '使用验证器保护后台账号' }}</p>
      </div>
      <el-tag v-if="status" :type="status.enabled ? 'success' : 'warning'" effect="plain">
        {{ status.enabled ? '已启用' : '未启用' }}
      </el-tag>
    </header>

    <div v-loading="loading" class="security-content">
      <template v-if="status?.enabled">
        <section class="status-band">
          <div>
            <span class="status-label">恢复码</span>
            <strong>{{ status.remainingRecoveryCodes }} 条可用</strong>
          </div>
          <el-button :icon="Refresh" @click="regenerateDialogVisible = true">重建恢复码</el-button>
        </section>

        <section v-if="!authStore.isAdmin" class="danger-section">
          <div>
            <h2>禁用多因素认证</h2>
            <p>禁用后，现有会话会全部失效。</p>
          </div>
          <el-button type="danger" plain :icon="Unlock" @click="disableDialogVisible = true">
            禁用 MFA
          </el-button>
        </section>
      </template>

      <template v-else-if="status">
        <section v-if="!enrollment" class="setup-section">
          <div class="section-heading">
            <h2>启用验证器</h2>
            <span>步骤 1 / 2</span>
          </div>
          <el-form :model="startForm" label-position="top" @submit.prevent>
            <el-form-item label="当前密码">
              <el-input
                v-model="startForm.password"
                type="password"
                autocomplete="current-password"
                maxlength="128"
                show-password
              />
            </el-form-item>
            <el-button
              type="primary"
              :icon="Lock"
              :loading="actionLoading"
              :disabled="!startForm.password"
              @click="startEnrollment"
            >
              开始设置
            </el-button>
          </el-form>
        </section>

        <section v-else class="setup-section enrollment-grid">
          <div class="section-heading grid-wide">
            <h2>绑定验证器</h2>
            <span>步骤 2 / 2</span>
          </div>

          <div class="qr-area">
            <img v-if="qrDataUrl" :src="qrDataUrl" alt="SkyLicense TOTP QR code" />
            <div v-else class="qr-placeholder">QR</div>
          </div>

          <div class="manual-area">
            <label>手动密钥</label>
            <div class="secret-row">
              <code>{{ enrollment.manualSecret }}</code>
              <el-button circle :icon="CopyDocument" title="复制手动密钥" @click="copyText(enrollment.manualSecret)" />
            </div>

            <el-form :model="confirmForm" label-position="top" @submit.prevent>
              <el-form-item label="6 位验证码">
                <el-input
                  v-model="confirmForm.factor"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  maxlength="6"
                />
              </el-form-item>
              <div class="form-actions">
                <el-button @click="cancelEnrollment">取消</el-button>
                <el-button
                  type="primary"
                  :loading="actionLoading"
                  :disabled="confirmForm.factor.length !== 6"
                  @click="confirmEnrollment"
                >
                  确认并启用
                </el-button>
              </div>
            </el-form>
          </div>
        </section>
      </template>
    </div>

    <el-dialog
      v-model="regenerateDialogVisible"
      title="重建恢复码"
      width="440px"
      destroy-on-close
      :close-on-click-modal="false"
    >
      <el-form :model="manageForm" label-position="top">
        <el-form-item label="当前密码">
          <el-input v-model="manageForm.password" type="password" autocomplete="current-password" maxlength="128" show-password />
        </el-form-item>
        <el-form-item label="验证码或恢复码">
          <el-input v-model="manageForm.factor" autocomplete="one-time-code" maxlength="64" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="regenerateDialogVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="actionLoading"
          :disabled="!manageForm.password || !manageForm.factor"
          @click="regenerateRecoveryCodes"
        >
          重建
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="disableDialogVisible"
      title="禁用多因素认证"
      width="440px"
      destroy-on-close
      :close-on-click-modal="false"
    >
      <el-form :model="manageForm" label-position="top">
        <el-form-item label="当前密码">
          <el-input v-model="manageForm.password" type="password" autocomplete="current-password" maxlength="128" show-password />
        </el-form-item>
        <el-form-item label="验证码或恢复码">
          <el-input v-model="manageForm.factor" autocomplete="one-time-code" maxlength="64" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="disableDialogVisible = false">取消</el-button>
        <el-button
          type="danger"
          :loading="actionLoading"
          :disabled="!manageForm.password || !manageForm.factor"
          @click="disableMfa"
        >
          确认禁用
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="recoveryDialogVisible"
      title="保存恢复码"
      width="520px"
      :close-on-click-modal="false"
      :close-on-press-escape="false"
      :show-close="false"
    >
      <div class="recovery-grid">
        <code v-for="code in recoveryCodes" :key="code">{{ code }}</code>
      </div>
      <template #footer>
        <el-button :icon="CopyDocument" @click="copyText(recoveryCodes.join('\n'))">复制</el-button>
        <el-button :icon="Download" @click="downloadRecoveryCodes">下载</el-button>
        <el-button type="primary" @click="finishRecoveryFlow">已安全保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { CopyDocument, Download, Lock, Refresh, Unlock } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
import * as authApi from '@/api/auth'
import { useAuthStore } from '@/stores/auth'
import type { MfaEnrollmentResponse, MfaStatusResponse } from '@/types'

const router = useRouter()
const authStore = useAuthStore()
const loading = ref(true)
const actionLoading = ref(false)
const status = ref<MfaStatusResponse | null>(null)
const enrollment = ref<MfaEnrollmentResponse | null>(null)
const qrDataUrl = ref('')
const regenerateDialogVisible = ref(false)
const disableDialogVisible = ref(false)
const recoveryDialogVisible = ref(false)
const recoveryCodes = ref<string[]>([])
const sessionRevoked = ref(false)

const startForm = reactive({ password: '' })
const confirmForm = reactive({ factor: '' })
const manageForm = reactive({ password: '', factor: '' })

async function loadStatus() {
  loading.value = true
  try {
    status.value = await authApi.getMfaStatus()
  } finally {
    loading.value = false
  }
}

async function startEnrollment() {
  actionLoading.value = true
  try {
    enrollment.value = await authApi.startMfaEnrollment({ password: startForm.password })
    startForm.password = ''
    try {
      qrDataUrl.value = await QRCode.toDataURL(enrollment.value.otpauthUri, {
        errorCorrectionLevel: 'M',
        margin: 1,
        width: 240,
        color: { dark: '#111827', light: '#ffffff' },
      })
    } catch {
      qrDataUrl.value = ''
    }
  } finally {
    actionLoading.value = false
  }
}

function cancelEnrollment() {
  enrollment.value = null
  qrDataUrl.value = ''
  confirmForm.factor = ''
}

async function confirmEnrollment() {
  actionLoading.value = true
  try {
    const result = await authApi.confirmMfaEnrollment({ factor: confirmForm.factor })
    recoveryCodes.value = result.recoveryCodes
    sessionRevoked.value = true
    recoveryDialogVisible.value = true
  } finally {
    actionLoading.value = false
  }
}

async function regenerateRecoveryCodes() {
  actionLoading.value = true
  try {
    const result = await authApi.regenerateMfaRecoveryCodes({ ...manageForm })
    regenerateDialogVisible.value = false
    recoveryCodes.value = result.recoveryCodes
    sessionRevoked.value = true
    recoveryDialogVisible.value = true
    resetManageForm()
  } finally {
    actionLoading.value = false
  }
}

async function disableMfa() {
  actionLoading.value = true
  try {
    await authApi.disableMfa({ ...manageForm })
    ElMessage.success('多因素认证已禁用，请重新登录')
    authStore.reset()
    await router.replace('/login')
  } finally {
    actionLoading.value = false
  }
}

async function copyText(value: string) {
  await navigator.clipboard.writeText(value)
  ElMessage.success('已复制')
}

function downloadRecoveryCodes() {
  const content = `SkyLicense recovery codes\n\n${recoveryCodes.value.join('\n')}\n`
  const url = URL.createObjectURL(new Blob([content], { type: 'text/plain;charset=utf-8' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = 'skylicense-recovery-codes.txt'
  anchor.click()
  URL.revokeObjectURL(url)
}

async function finishRecoveryFlow() {
  recoveryDialogVisible.value = false
  recoveryCodes.value = []
  if (sessionRevoked.value) {
    authStore.reset()
    await router.replace('/login')
  }
}

function resetManageForm() {
  manageForm.password = ''
  manageForm.factor = ''
}

onMounted(() => loadStatus())
</script>

<style scoped lang="scss">
.security-page {
  max-width: 840px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1.5rem;

  h1 {
    margin: 0 0 0.35rem;
    color: var(--color-text-primary);
    font-size: 1.5rem;
    letter-spacing: 0;
  }

  p {
    margin: 0;
    color: var(--color-text-secondary);
    font-size: 0.875rem;
  }
}

.security-content {
  min-height: 280px;
}

.status-band,
.danger-section,
.setup-section {
  border: 1px solid var(--color-border);
  border-radius: 6px;
  background: var(--color-bg-card);
  padding: 1.5rem;
}

.status-band,
.danger-section {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

.status-band {
  margin-bottom: 1rem;

  > div {
    display: grid;
    gap: 0.3rem;
  }
}

.status-label {
  color: var(--color-text-muted);
  font-size: 0.75rem;
}

.danger-section {
  border-color: var(--color-danger-light);

  h2,
  p {
    margin: 0;
  }

  h2 {
    color: var(--color-text-primary);
    font-size: 1rem;
    letter-spacing: 0;
  }

  p {
    margin-top: 0.35rem;
    color: var(--color-text-secondary);
    font-size: 0.8125rem;
  }
}

.setup-section {
  max-width: 620px;
}

.section-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.25rem;

  h2 {
    margin: 0;
    color: var(--color-text-primary);
    font-size: 1rem;
    letter-spacing: 0;
  }

  span {
    color: var(--color-text-muted);
    font-size: 0.75rem;
  }
}

.enrollment-grid {
  display: grid;
  grid-template-columns: 240px minmax(0, 1fr);
  gap: 1.5rem;
  max-width: 760px;
}

.grid-wide {
  grid-column: 1 / -1;
  margin-bottom: 0;
}

.qr-area {
  width: 240px;
  height: 240px;
  border: 1px solid var(--color-border);
  background: #fff;

  img,
  .qr-placeholder {
    width: 100%;
    height: 100%;
  }

  .qr-placeholder {
    display: grid;
    place-items: center;
    color: #6b7280;
  }
}

.manual-area {
  min-width: 0;

  > label {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--color-text-secondary);
    font-size: 0.8125rem;
  }
}

.secret-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1.25rem;

  code {
    flex: 1;
    min-width: 0;
    overflow-wrap: anywhere;
    border: 1px solid var(--color-border);
    border-radius: 4px;
    background: var(--color-bg-page);
    padding: 0.7rem;
    color: var(--color-text-primary);
    font-size: 0.8125rem;
  }
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
}

.recovery-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.65rem;

  code {
    border: 1px solid var(--color-border);
    border-radius: 4px;
    background: var(--color-bg-page);
    padding: 0.65rem;
    text-align: center;
    color: var(--color-text-primary);
    font-size: 0.8125rem;
  }
}

@media (max-width: 700px) {
  .status-band,
  .danger-section {
    align-items: stretch;
    flex-direction: column;
  }

  .enrollment-grid {
    grid-template-columns: 1fr;
  }

  .grid-wide {
    grid-column: auto;
  }

  .qr-area {
    width: min(240px, 100%);
    height: auto;
    aspect-ratio: 1;
    justify-self: center;
  }

  .recovery-grid {
    grid-template-columns: 1fr;
  }
}
</style>
