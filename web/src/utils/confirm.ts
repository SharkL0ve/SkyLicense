import { ElMessageBox } from 'element-plus'

export async function confirmAction(message: string, title = '操作确认'): Promise<boolean> {
  try {
    await ElMessageBox.confirm(message, title, {
      type: 'warning',
      confirmButtonText: '确认',
      cancelButtonText: '取消',
    })
    return true
  } catch {
    return false
  }
}
