export const AUTH_RESULTS = [
  { value: 'OK', label: '验证成功', type: 'success' },
  { value: 'PENDING', label: '等待资源释放', type: 'warning' },
  { value: 'RELEASED', label: '资源已释放，等待确认', type: 'warning' },
  { value: 'FAILED', label: '许可证不存在', type: 'danger' },
  { value: 'BANNED', label: '已封禁', type: 'danger' },
  { value: 'BANNED_BY_IP', label: 'IP封禁', type: 'danger' },
  { value: 'BANNED_BY_QQ', label: 'QQ封禁', type: 'danger' },
  { value: 'BANNED_BY_HWID', label: '机器码封禁', type: 'danger' },
  { value: 'BANNED_BY_CODE', label: '许可证封禁', type: 'danger' },
  { value: 'PROGRAM_DISABLED', label: '程序已禁用', type: 'danger' },
  { value: 'PROGRAM_MISMATCH', label: '程序不匹配', type: 'danger' },
  { value: 'LICENSE_OWNER_MISMATCH', label: '许可证归属不一致', type: 'danger' },
  { value: 'USER_DISABLED', label: '程序所有者已禁用', type: 'danger' },
  { value: 'IP_LIMIT', label: 'IP绑定已满', type: 'warning' },
  { value: 'HWID_LIMIT', label: '机器码绑定已满', type: 'warning' },
  { value: 'IP_MISSING', label: '缺少IP信息', type: 'warning' },
  { value: 'HWID_MISSING', label: '缺少机器码信息', type: 'warning' },
  { value: 'BINDING_REVOKED', label: '绑定已撤销', type: 'warning' },
  { value: 'EXPIRED', label: '已过期', type: 'info' },
  { value: 'DAILY_AUTH_LIMIT', label: '当日验证次数已满', type: 'warning' },
  { value: 'DELIVERY_FAILED', label: '资源释放前失败', type: 'danger' },
  { value: 'DELIVERY_UNCONFIRMED', label: '资源已释放但未确认', type: 'danger' },
] as const

export const BAN_TYPES = [
  { value: 'IP', label: 'IP地址' },
  { value: 'HWID', label: '机器码' },
  { value: 'QQ', label: 'QQ号' },
  { value: 'CODE', label: '许可证' },
] as const

export const USER_ROLES = [
  { value: 'USER', label: '普通用户' },
  { value: 'ADMIN', label: '管理员' },
] as const
