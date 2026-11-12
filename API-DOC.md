# SkyLicense Web API 接口文档

> 版本: 1.5.0<br>
> 基础路径: `https://{host}:{webPort}`（强制 TLS 1.3）<br>
> 默认端口: 8080（可在 config.json 中配置 webPort）<br>
> 认证方式: HttpOnly 会话 Cookie + 会话绑定 CSRF Token<br>
> 业务时间格式: `yyyy-MM-dd-HH:mm`；操作审计时间为规范 UTC `Instant`

---

## 目录

1. [通用说明](#通用说明)
2. [健康检查](#0-健康检查)
3. [认证接口](#1-认证接口)
4. [程序管理](#2-程序管理)
5. [授权码管理](#3-授权码管理)
6. [封禁管理](#4-封禁管理)
7. [用户管理（管理员）](#5-用户管理管理员)
8. [系统管理（管理员）](#6-系统管理管理员)
9. [数据模型](#7-数据模型)

---

## 通用说明

### 认证

登录成功后服务端通过 `Set-Cookie` 写入 `__Host-skylicense_session`。Cookie
固定使用 `Secure`、`HttpOnly` 和 `Path=/`，Cookie 只包含 256 位 opaque 随机值，浏览器 JavaScript 无法读取。
同源部署使用 `SameSite=Strict`；配置分离前端 Origin 时使用
`SameSite=None`，并继续受精确 CORS Origin 约束。

浏览器请求必须启用凭据发送。除 `GET`、`HEAD` 和 `OPTIONS` 外，所有请求
还必须携带登录或 `GET /api/auth/session` 返回的会话绑定令牌：

```http
X-CSRF-Token: <csrfToken>
```

服务端同时校验 CSRF Token 和 `Origin`。命令行客户端可使用 Cookie jar；
没有 `Origin` 时仍必须提供 CSRF 请求头。升级后不再接受 Bearer/JWT 会话，
旧 `localStorage` 会话需要重新登录。

会话 Cookie 的授权记录持久化在服务端 SQLite `web_session` 表中。表内只
保存 Cookie SHA-256 摘要、用户 ID 和独立 CSRF 值，不保存原始 Cookie；登出
删除记录，服务端重启后不会恢复已撤销会话。每用户最多 20 个并发会话。

登录失败计数以账号和来源地址的域分离 HMAC 引用保存在 `web_login_attempt`，服务
重启不会清除锁定。MFA 登录挑战只保存随机令牌摘要；TOTP 种子由独立安装密钥使用
AES-256-GCM 加密，恢复码仅保存带随机盐的 PBKDF2 哈希。

启用/确认 MFA、重建恢复码、禁用 MFA 和管理员重置用户 MFA 还共享独立的
`MFA_MANAGEMENT` 限流域：每个账号 5 次失败后锁定 5 分钟，状态同样持久化在
`web_login_attempt`，不会因为服务重启清零。成功完成一次管理操作后该域计数清除。

`ADMIN` 未启用 MFA 时，其会话只允许访问 `GET /api/auth/session`、
`GET /api/auth/me`、`GET /api/auth/mfa/status`、MFA enrollment 开始/确认、
修改密码和登出。其他 API 返回 `403`；管理员不能通过自助接口禁用 MFA。

### 统一响应格式

```json
{
  "code": 200,
  "message": "success",
  "data": {},
  "timestamp": 1716000000000
}
```

### 错误响应

错误响应的 HTTP 状态与响应体 `code` 一致，例如未认证为 HTTP 401、无权限为
HTTP 403、资源不存在为 HTTP 404。调用方不能再假设所有业务错误都返回 HTTP 200；
应同时处理 HTTP 状态和下方 JSON 错误信封。

```json
{
  "code": 401,
  "message": "会话无效或已过期",
  "data": null,
  "timestamp": 1716000000000
}
```

常见错误码：
| code | 含义 |
|------|------|
| 200 | 成功 |
| 400 | 参数校验失败 |
| 401 | 未认证/会话无效 |
| 403 | 无权限 |
| 404 | 资源不存在 |
| 409 | 数据库唯一性或完整性约束冲突；响应不包含 SQL 详情 |
| 429 | 请求过于频繁 |
| 500 | 服务器内部错误 |

### 分页参数

所有列表接口支持以下分页参数：

| 参数       | 类型  | 默认值 | 说明               |
|----------|-----|-----|------------------|
| page     | int | 1   | 页码，最小值 1         |
| pageSize | int | 20  | 每页条数，最小 1，最大 200 |

分页响应格式：
```json
{
  "records": [],
  "total": 100,
  "page": 1,
  "pageSize": 20,
  "totalPages": 5
}
```

### 角色说明

| 角色    | 说明                 |
|-------|--------------------|
| USER  | 普通用户，只能管理自己的程序和授权码 |
| ADMIN | 管理员，可管理所有用户、程序、授权码 |

### 原生认证完成语义

服务端在资源发送前创建短暂的 `PENDING` 预留。准备实际写出加密资源时，服务端
在同一事务中提交许可证的 `ips`、`hwids`、`lastAuthTime` 和每日额度，并将日志改为
`RELEASED`，然后才向网络写入密文。客户端控制的 `SKDA` ACK 只负责把
`RELEASED` 确认为 `OK`，不能撤销已经释放的资源。资源写出前失败会记为
`DELIVERY_FAILED`，不占用绑定或额度；资源已经释放但断连、ACK 超时（30 秒）、
签名错误、入口失败或确认帧写失败会记为 `DELIVERY_UNCONFIRMED`，保留绑定和额度，
并销毁会话。服务端启动时会将遗留的 `PENDING` 恢复为 `DELIVERY_FAILED`，将遗留的
`RELEASED` 恢复为 `DELIVERY_UNCONFIRMED`。

---

## 0. 健康检查

健康端点位于 `/api` 之外，不使用后台会话 Cookie 或 CSRF Token，响应统一携带
`Cache-Control: no-store`。它们只适合受控监控来源，不会返回内部错误原因。

### 0.1 存活探针

```http
GET /health/live
```

只要 Web 进程能够处理请求就返回 HTTP 200：

```json
{"status":"UP"}
```

### 0.2 就绪探针

```http
GET /health/ready
```

服务未进入关闭流程、原生 TLS 认证监听器正在接受连接、SQLite 最小查询成功且操作
审计持久化健康时，返回 HTTP 200 和 `{"status":"UP"}`。任一条件不满足时返回 HTTP 503：

```json
{"status":"DOWN"}
```

数据库检查结果最多缓存约 2 秒。监控程序必须执行正常的 CA、主机名和 TLS 1.3
校验；不得使用跳过证书校验的选项。

---

## 1. 认证接口

### 1.1 登录

```
POST /api/auth/login
```

**请求体：**
```json
{
  "username": "admin",
  "password": "your_password"
}
```

| 字段       | 类型     | 必填 | 说明  |
|----------|--------|----|-----|
| username | string | 是  | 用户名；自动去除首尾空格，登录匹配不区分 ASCII 大小写 |
| password | string | 是  | 密码  |

**成功响应：**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "csrfToken": "43-character-csrf-token",
    "expiresInSeconds": 86400,
    "mfaRequired": false,
    "challengeToken": null
  },
  "timestamp": 1716000000000
}
```

启用 MFA 的账号密码正确时不设置 Cookie，也不创建会话，返回：

```json
{
  "csrfToken": null,
  "expiresInSeconds": 300,
  "mfaRequired": true,
  "challengeToken": "43-character-random-challenge"
}
```

调用方必须把 `challengeToken` 仅保存在当前登录表单内，并调用
`POST /api/auth/mfa/verify`。挑战只以 SHA-256 摘要保存，有效期 5 分钟且最多失败 5 次。

**错误响应：**
- `401` 用户名或密码错误
- `403` 账号已被禁用
- `429` 登录失败次数过多（账号 5 次失败后锁定 5 分钟；来源地址有独立上限）

**响应头：** `Set-Cookie: __Host-skylicense_session=...; Path=/; Secure; HttpOnly; SameSite=Strict`

---

### 1.2 登出

```
POST /api/auth/logout
```

**说明：** 需要 `X-CSRF-Token`，撤销当前会话并清除 HttpOnly Cookie。

**成功响应：**
```json
{
  "code": 200,
  "message": "已登出",
  "data": null,
  "timestamp": 1716000000000
}
```

---

### 1.3 获取当前会话

```
GET /api/auth/session
```

**成功响应 data：**

```json
{
  "user": {
    "id": 1,
    "username": "admin",
    "role": "ADMIN",
    "maxPrograms": 999,
    "status": 1,
    "mfaEnabled": 1
  },
  "csrfToken": "43-character-csrf-token"
}
```

页面刷新后应先调用此接口，同时恢复用户信息和内存中的 CSRF Token。

---

### 1.4 获取当前用户信息

```
GET /api/auth/me
```

**成功响应：**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "id": 1,
    "username": "admin",
    "role": "ADMIN",
    "maxPrograms": 999,
    "status": 1,
    "createTime": "2024-01-01-00:00",
    "lastLoginTime": "2024-06-01-12:00",
    "email": null,
    "mfaEnabled": 1,
    "mfaUpdatedAt": 1716000000000
  },
  "timestamp": 1716000000000
}
```

---

### 1.5 修改密码

```
PUT /api/auth/password
```

**请求体：**
```json
{
  "oldPassword": "current_password",
  "newPassword": "new_secure_password123"
}
```

| 字段          | 类型     | 必填 | 约束              |
|-------------|--------|----|-----------------|
| oldPassword | string | 是  | -               |
| newPassword | string | 是  | 12-128位，至少包含三类字符 |

修改成功后当前 Cookie 会被清除，客户端必须重新登录。

### 1.6 完成 MFA 登录挑战

```http
POST /api/auth/mfa/verify
```

该端点不需要现有会话，但执行与登录相同的 `Origin` 校验。

```json
{
  "challengeToken": "43-character-random-challenge",
  "factor": "123456"
}
```

`factor` 可以是 6 位 TOTP，也可以是一条未使用的恢复码。成功响应与普通登录相同，
`mfaRequired=false` 并通过 `Set-Cookie` 建立会话。TOTP 时间窗为 30 秒、允许前后各一个
时间片，并拒绝已经接受过的时间片；恢复码成功使用后立即从数据库删除。

### 1.7 查询 MFA 状态

```http
GET /api/auth/mfa/status
```

```json
{"enabled": true, "remainingRecoveryCodes": 9}
```

### 1.8 开始 MFA enrollment

```http
POST /api/auth/mfa/enrollment
```

```json
{"password": "current_password"}
```

返回只用于本次设置的 `manualSecret`、`otpauthUri` 和 600 秒有效期。数据库只保存
AES-256-GCM 密文，响应中的秘密不得写入日志或持久化到浏览器存储。

### 1.9 确认 MFA enrollment

```http
POST /api/auth/mfa/enrollment/confirm
```

```json
{"factor": "123456"}
```

成功时返回 10 条只显示一次的 `recoveryCodes`，同时撤销该用户的全部会话与挑战并清除
当前 Cookie。调用方应先让用户安全保存恢复码，再跳转到登录页。

### 1.10 重建恢复码

```http
POST /api/auth/mfa/recovery-codes
```

```json
{"password": "current_password", "factor": "123456"}
```

旧恢复码全部作废，新恢复码只返回一次；所有会话和挑战均被撤销。

### 1.11 禁用 MFA

```http
DELETE /api/auth/mfa
```

```json
{"password": "current_password", "factor": "123456"}
```

仅普通用户可以调用。成功后清除加密 TOTP 种子和恢复码，并撤销所有会话与挑战；
管理员调用返回 `403`，需要由另一名管理员使用“重置用户 MFA”接口恢复。

---

## 2. 程序管理

### 2.1 获取程序列表

```
GET /api/programs?page=1&pageSize=20
```

**说明：** 普通用户只能看到自己的程序，管理员可看到所有程序。

**成功响应 data：** `PageResult<Program>`

---

### 2.2 创建程序

```
POST /api/programs
```

**请求体：**
```json
{
  "name": "MyPlugin",
  "description": "我的插件描述"
}
```

| 字段          | 类型     | 必填 | 说明            |
|-------------|--------|----|---------------|
| name        | string | 是  | 1–64 位安全 ASCII 名称；全局大小写不敏感唯一，可使用字母、数字、点、下划线、加号和连字符 |
| description | string | 否  | 描述            |

**错误：**
- `400` 已达到最大程序数量限制
- `400` 程序名称已存在
- `400` 已上传版本的程序不能重命名

---

### 2.3 获取程序详情

```
GET /api/programs/{id}
```

---

### 2.4 修改程序

```
PUT /api/programs/{id}
```

**请求体：** 所有字段均可选；省略字段保持原值。已有版本后不能修改名称。

```json
{
  "name": "MyPlugin-renamed",
  "description": "updated description"
}
```

---

### 2.5 删除程序

```
DELETE /api/programs/{id}
```

---

### 2.6 切换程序状态

```
PUT /api/programs/{id}/status?status=0
```

| 参数       | 说明 |
|----------|----|
| status=1 | 启用 |
| status=0 | 禁用 |

---

### 2.7 获取程序版本列表

```
GET /api/programs/{id}/versions
```

**成功响应 data：** `List<ProgramVersion>`

---

### 2.8 上传新版本

```
POST /api/programs/{id}/versions?version=1.0.0
Content-Type: multipart/form-data
```

| 参数      | 类型             | 必填 | 说明              |
|---------|----------------|----|-----------------|
| version | string (query) | 是  | 版本号             |
| file    | file (form)    | 是  | JAR 文件（最大64 MiB） |

**说明：** JAR 根目录必须包含唯一的 `settings.yml`。其中 `Name` 必须与 Web 程序名完全一致，`Version` 必须与上传参数完全一致；`EntryClass` 必须存在于 JAR 中，`EntryPoint` 必须对应 `public static void` 无参数入口方法，否则拒绝上传。`KeepClasses` 匹配的类跳过方法改写和随机字节码变异；`InfPort` 仅用于旧文件兼容。

**错误：**
- `400` 只支持上传 JAR 文件
- `400` 版本已存在
- `400` JAR 文件格式无效

---

### 2.9 删除版本

```
DELETE /api/programs/{id}/versions/{vid}
```

删除成功后，服务端会从活动资源快照移除该 `Name/Version`，并标记已经使用该版本的原生租约为撤销状态。客户端下一次认证心跳会收到签名 `REVOKE` 并停止受保护分发；未删除版本的在线租约不受影响。

---

## 3. 授权码管理

### 3.1 获取程序的授权码列表（支持筛选）

```
GET /api/programs/{programId}/licenses?page=1&pageSize=20&status=active&qq=123456&sortBy=createTime&order=desc
```

**查询参数：**

| 参数      | 类型     | 说明                                                    |
|---------|--------|-------------------------------------------------------|
| status  | string | 筛选状态：`active`（正常）、`banned`（封禁）、不传则全部                  |
| qq      | string | 按QQ号精确筛选；新数据为1-20位数字，旧数据仍可读取                     |
| ip      | string | 按IP模糊筛选（包含该IP的授权码）                                    |
| hwid    | string | 按机器码模糊筛选                                              |
| keyword | string | 关键词搜索（搜索 code、qq、notes）                               |
| sortBy  | string | 排序字段：`createTime`、`lastAuthTime`、`code`、`qq`、`status` |
| order   | string | 排序方向：`asc`、`desc`（默认 desc）                            |

---

### 3.2 创建授权码

```
POST /api/programs/{programId}/licenses
```

**请求体：**
```json
{
  "code": "CUSTOM-CODE-001",
  "qq": "123456789",
  "bindableIps": 2,
  "bindableHwids": 1,
  "expirationDate": "2027-12-31-23:59",
  "maxDailyAuth": 5,
  "notes": "VIP用户"
}
```

| 字段            | 类型     | 必填 | 默认值      | 说明              |
|---------------|--------|----|----------|-----------------|
| code          | string | 否  | 自动生成UUID | 自定义授权码          |
| qq            | string | 否  | -        | 关联QQ号，1-20位数字       |
| bindableIps   | int    | 否  | 1        | 可绑定IP数（0=不限制IP） |
| bindableHwids | int    | 否  | 0        | 可绑定机器码数（0=不限制）  |
| expirationDate | string | 否  | null     | 到期时间，格式 `yyyy-MM-dd-HH:mm` |
| maxDailyAuth  | int    | 否  | 0        | 每日成功启动认证上限，0=不限制 |
| notes         | string | 否  | -        | 备注              |

**成功响应 data：** `License` 对象

---

### 3.3 获取授权码详情

```
GET /api/licenses/{code}
```

**成功响应 data：**
```json
{
  "id": 1,
  "code": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "programId": 1,
  "userId": 1,
  "qq": "123456789",
  "bindableIps": 2,
  "bindableHwids": 1,
  "status": 1,
  "ips": "192.168.1.1,10.0.0.1",
  "hwids": "HWID-ABC-123",
  "createTime": "2024-01-01-00:00",
  "lastAuthTime": "2024-06-01-12:00",
  "banReason": null,
  "notes": "VIP用户",
  "expirationDate": null,
  "maxDailyAuth": 0,
  "lastModifiedTime": "2024-06-01-12:00"
}
```

---

### 3.4 修改授权码

```
PUT /api/licenses/{code}
```

**请求体：** 支持 `qq`、`bindableIps`、`bindableHwids`、`expirationDate`、`maxDailyAuth` 和 `notes`，字段均可选。空字符串可清除 QQ、到期时间或备注；省略字段保持原值。将非零 IP 或机器码上限降低到当前已绑定数量以下会被拒绝，必须先通过解绑接口移除多余绑定；更新与原生授权提交共用同一临界区，不会与在途资源释放产生超额绑定。

---

### 3.5 删除授权码

```
DELETE /api/licenses/{code}
```

---

### 3.6 解绑 IP/机器码

```
PUT /api/licenses/{code}/unbind
```

**请求体：**
```json
{
  "ip": "192.168.1.1",
  "hwid": null,
  "all": false
}
```

| 字段   | 类型      | 说明            |
|------|---------|---------------|
| ip   | string  | 要解绑的单个IP      |
| hwid | string  | 要解绑的单个HWID    |
| all  | boolean | `true`=清空所有绑定 |

**说明：** `all=true` 时忽略 ip 和 hwid 字段，直接清空所有绑定。解绑与相关
`PENDING` 预留和已释放但尚未确认的 `RELEASED` 会话在同一事务内失效，因此在途
ACK 不能在解绑后重新写回绑定；已释放的尝试不会退回每日额度。

**成功响应 data：** 更新后的 `License` 对象

---

### 3.7 封禁授权码

```
PUT /api/licenses/{code}/ban?reason=违规使用
```

| 参数     | 说明       |
|--------|----------|
| reason | 封禁原因（可选） |

---

### 3.8 解封授权码

```
PUT /api/licenses/{code}/unban
```

---

### 3.9 获取验证历史

```
GET /api/licenses/{code}/logs?page=1&pageSize=20
```

**成功响应 data：** `PageResult<AuthLog>`

```json
{
  "records": [
    {
      "id": 1,
      "licenseId": 1,
      "code": "xxx-xxx",
      "ip": "192.168.1.1",
      "hwid": "HWID-ABC",
      "result": "OK",
      "timestamp": "2024-06-01-12:00",
      "programId": 1,
      "userId": 1
    }
  ],
  "total": 50,
  "page": 1,
  "pageSize": 20,
  "totalPages": 3
}
```

**result 可能的值：**
| 值 | 含义 |
|---|------|
| OK | 客户端资源已解密加载、心跳和入口已成功初始化，且服务端已确认签名 ACK |
| PENDING | 尚未释放资源的短暂预留；计入当前每日额度预留 |
| RELEASED | 资源已释放，绑定和额度已提交，正在等待 ACK |
| FAILED | 授权码不存在 |
| BANNED | 被封禁 |
| BANNED_BY_IP | 命中IP封禁 |
| BANNED_BY_QQ | 命中QQ封禁 |
| BANNED_BY_HWID | 命中HWID封禁 |
| BANNED_BY_CODE | 命中授权码封禁 |
| IP_LIMIT | IP绑定数已满 |
| HWID_LIMIT | 机器码绑定数已满 |
| EXPIRED | 授权码已过期 |
| DAILY_AUTH_LIMIT | 当日成功启动认证次数已满 |
| DELIVERY_FAILED | 资源释放前失败；不占用绑定或每日额度 |
| DELIVERY_UNCONFIRMED | 资源已释放但客户端未完成 ACK、入口或确认阶段；保留绑定和每日额度 |
| PROGRAM_DISABLED | 程序不存在或已禁用 |
| PROGRAM_MISMATCH | 授权码不属于请求程序 |
| LICENSE_OWNER_MISMATCH | 授权码和程序所有者不一致 |
| USER_DISABLED | 程序所有者不存在或已禁用 |
| IP_MISSING / HWID_MISSING | 启用相应绑定策略但客户端信息缺失 |
| BINDING_REVOKED | 活动会话的绑定已被管理员移除 |

---

### 3.10 批量封禁

```
PUT /api/licenses/batch/ban
```

**请求体：**
```json
{
  "codes": ["code1", "code2", "code3"],
  "reason": "批量封禁原因"
}
```

**成功响应 data：**
```json
{ "affected": 3 }
```

---

### 3.11 批量解封

```
PUT /api/licenses/batch/unban
```

**请求体：**
```json
{
  "codes": ["code1", "code2"]
}
```

---

### 3.12 批量删除

```
DELETE /api/licenses/batch
```

**请求体：**
```json
{
  "codes": ["code1", "code2"]
}
```

---

### 3.13 为多个程序创建许可证

```
POST /api/licenses/multi
```

请求体在创建许可证字段基础上增加 `programIds`。系统为每个程序创建独立许可证；自定义 `code` 在多程序场景自动追加程序 ID。普通用户只能选择自己的程序。

### 3.14 获取当前用户的全部验证日志

```
GET /api/auth-logs?page=1&pageSize=20&programId=1&code=CODE&result=OK
```

支持 `programId`、`code`、`ip`、`hwid`、`result`、`startTime` 和 `endTime` 筛选。管理员调用时返回全部用户记录。

### 3.15 获取指定程序的验证日志

```
GET /api/programs/{id}/auth-logs?page=1&pageSize=20&result=OK
```

仅程序所有者或管理员可访问，筛选字段同 3.14。

---

## 4. 封禁管理

### 4.1 创建封禁

```
POST /api/bans
```

**请求体：**
```json
{
  "type": "IP",
  "value": "192.168.1.100",
  "reason": "恶意访问",
  "programId": 1,
  "expirationDate": "2024-12-31-23:59"
}
```

| 字段             | 类型     | 必填 | 说明                           |
|----------------|--------|----|------------------------------|
| type           | string | 是  | 封禁类型：`IP`、`HWID`、`QQ`、`CODE` |
| value          | string | 是  | IP/HWID/QQ/CODE；QQ为1-20位数字，CODE为1-256位安全字符 |
| reason         | string | 否  | 封禁原因                         |
| programId      | long   | 普通用户必填 | 规则作用程序；管理员省略时为全局规则 |
| expirationDate | string | 否  | 过期时间，null=永久封禁               |

**封禁效果：**
| 类型 | 效果 |
|------|------|
| CODE | 在规则作用域内直接封禁该授权码 |
| QQ | 在规则作用域内封禁该QQ下的授权码 |
| IP | 在规则作用域内封禁已绑定该IP的授权码，并拒绝该IP首次认证 |
| HWID | 在规则作用域内封禁已绑定该HWID的授权码，并拒绝该HWID首次认证 |

**验证时的封禁检查逻辑：**
当客户端验证时，系统会检查：
1. 授权码本身是否在封禁记录中
2. 授权码关联的QQ是否在封禁记录中
3. 当前验证IP及授权码已绑定的所有IP是否在封禁记录中
4. 当前验证HWID及授权码已绑定的所有HWID是否在封禁记录中

命中任何一条即拒绝验证。相同封禁值可以在不同程序创建独立规则；普通用户不能创建跨程序全局规则。

返回的封禁记录包含 `status`：`1` 为生效，`0` 为已解除或已到期。服务启动时以及每分钟
后台任务会把 `expirationDate` 已到的生效规则原子置为 `0`，并重新计算受影响许可证。
多个规则同时覆盖同一许可证时，删除或到期其中一条不会提前恢复许可证，直到最后一条
生效规则消失。

---

### 4.2 获取封禁列表

```
GET /api/bans?type=IP&page=1&pageSize=20
```

| 参数   | 说明                                |
|------|-----------------------------------|
| type | 按类型筛选：`IP`、`HWID`、`QQ`、`CODE`（可选） |

**说明：** 普通用户只能看到自己创建的封禁记录，管理员可看到全部。

---

### 4.3 获取程序的封禁列表

```
GET /api/bans/program/{programId}?page=1&pageSize=20
```

---

### 4.4 解除封禁

```
DELETE /api/bans/{id}
```

**说明：** 解除封禁时，系统会自动恢复因该封禁记录而被封禁的授权码状态。

---

## 5. 用户管理（管理员）

> 以下接口需要 ADMIN 角色

### 5.1 获取用户列表

```
GET /api/users?page=1&pageSize=20
```

---

### 5.2 创建用户

```
POST /api/users
```

**请求体：**
```json
{
  "username": "newuser",
  "password": "password123",
  "role": "USER",
  "maxPrograms": 5
}
```

| 字段          | 类型     | 必填 | 默认值  | 说明              |
|-------------|--------|----|------|-----------------|
| username    | string | 是  | -    | 3-64位安全ASCII；支持字母、数字、点、下划线和连字符；去除首尾空格后大小写不敏感唯一 |
| password    | string | 是  | -    | 密码（12-128位，至少三类字符） |
| role        | string | 否  | USER | 角色：USER / ADMIN |
| maxPrograms | int    | 否  | 5    | 最大程序数量          |

---

### 5.3 获取用户详情

```
GET /api/users/{id}
```

---

### 5.4 修改用户

```
PUT /api/users/{id}
```

**请求体：** 字段可选，省略字段保持原值。

```json
{
  "username": "renamed-user",
  "password": "new-strong-password",
  "role": "USER",
  "maxPrograms": 10
}
```

修改用户名、密码或角色后，该用户的所有 Web 会话会在同一事务中撤销。新用户名
执行与创建相同的安全字符、首尾空格和大小写不敏感唯一校验。
系统拒绝降级、禁用或删除最后一个已启用的管理员账号。

---

### 5.5 删除用户

```
DELETE /api/users/{id}
```

**说明：** 级联删除用户的所有程序、版本、授权码、验证日志、封禁记录。操作日志保留用于审计。

---

### 5.6 切换用户状态

```
PUT /api/users/{id}/status?status=0
```

| 参数       | 说明          |
|----------|-------------|
| status=1 | 启用          |
| status=0 | 禁用（禁用后无法登录） |

---

### 5.7 管理员重置用户 MFA

```http
DELETE /api/users/{id}/mfa
```

**权限与安全条件：** 仅已完成 MFA 的 `ADMIN` 可以调用，`{id}` 不能是当前管理员自己；
目标用户必须已经启用 MFA。请求管理员必须重新提供当前密码，以及当前 TOTP 或一条未
使用的恢复码。未完成 MFA enrollment 的管理员会在会话过滤器处收到 `403`，只能先完成
自己的 enrollment。

**请求体：**

```json
{
  "password": "current-admin-password",
  "factor": "123456"
}
```

成功后只清除目标用户的加密 TOTP 种子、恢复码和待处理 enrollment，并撤销目标用户的
全部 Web 会话与 MFA 挑战；执行操作的管理员会话不会被撤销。管理员的 TOTP 时间片或
恢复码状态会在同一事务中更新，重复使用同一因素会失败。

常见响应：`401` 管理员密码或第二因素错误，`403` 非管理员或尝试重置自己，`404` 用户
不存在，`400` 目标未启用 MFA。若管理员同时丢失当前 MFA 和全部恢复码，只能由另一名
已验证的管理员执行此接口；不要直接修改 SQLite。生产部署应至少保留两名独立管理员。

---

### 5.8 获取用户操作历史

```
GET /api/users/{id}/operations?page=1&pageSize=20
```

**成功响应 data：** `PageResult<OperationLog>`

```json
{
  "records": [
    {
      "id": 1,
      "userId": 1,
      "username": "admin",
      "action": "CREATE_LICENSE",
      "target": "license",
      "detail": "{\"programId\":1,\"request\":{\"code\":\"ref:...\"}}",
      "ip": "ref:3f774d4f0197d3a135cbf65d2c0a0f59...",
      "timestamp": "2024-06-01-12:00"
    }
  ]
}
```

**action 类型：**
| action | 说明 |
|--------|------|
| CREATE_LICENSE | 创建授权码 |
| UPDATE_LICENSE | 修改授权码 |
| DELETE_LICENSE | 删除授权码 |
| BAN_LICENSE | 封禁授权码 |
| UNBAN_LICENSE | 解封授权码 |
| UNBIND_LICENSE | 解绑授权码 |
| BATCH_BAN_LICENSE | 批量封禁 |
| BATCH_UNBAN_LICENSE | 批量解封 |
| BATCH_DELETE_LICENSE | 批量删除 |
| CREATE_PROGRAM | 创建程序 |
| UPDATE_PROGRAM | 修改程序 |
| DELETE_PROGRAM | 删除程序 |
| TOGGLE_PROGRAM_STATUS | 切换程序状态 |
| UPLOAD_VERSION | 上传版本 |
| CREATE_BAN | 创建封禁 |
| DELETE_BAN | 解除封禁 |
| CREATE_USER | 创建用户 |
| UPDATE_USER | 修改用户 |
| DELETE_USER | 删除用户 |
| TOGGLE_USER_STATUS | 切换用户状态 |
| ADMIN_RESET_MFA | 管理员重置用户 MFA |

---

## 6. 系统管理（管理员）

> 以下接口需要 ADMIN 角色

### 6.1 获取所有程序

```
GET /api/admin/programs?page=1&pageSize=20
```

---

### 6.2 获取所有授权码

```
GET /api/admin/licenses?page=1&pageSize=20
```

---

### 6.3 管理员创建授权码

```
POST /api/admin/licenses
```

**请求体示例：**
```json
{
  "programIds": [1, 2],
  "allPrograms": false,
  "bindableIps": 1,
  "bindableHwids": 1,
  "expirationDate": null,
  "maxDailyAuth": 0
}
```

**说明：** 管理员可为任意程序或所有程序创建独立授权码，许可证自动归属程序所有者。`allPrograms=true` 时可省略或传空 `programIds`。

---

### 6.4 获取所有操作日志

```
GET /api/admin/operations?page=1&pageSize=20
```

返回 `PageResult<OperationLog>`。公开响应包含事件 ID、结果和开始/完成时间，但有意
省略内部 `chainPreviousMac`、`chainMac`、`integrityMac` 以及 checkpoint MAC；这些
认证材料只在服务端内部用于验证，不能作为 Web API 导出格式。

---

### 6.5 校验操作审计链完整性

```
GET /api/admin/operations/integrity
```

该接口执行一次完整的保留日志链验证，仅允许管理员访问。成功响应示例：

```json
{
  "verified": true,
  "rowCount": 1250,
  "anchorId": 0,
  "headId": 1250,
  "checkedAtMillis": 1784800000000,
  "status": "VERIFIED"
}
```

验证失败时仍返回不含内部原因和 MAC 的通用结果：`verified=false`、
`status=AUDIT_INTEGRITY_FAILED`。同时 `/health/ready` 降为 HTTP 503，运维人员应停止
后台写操作，保存数据库与 WAL/SHM sidecar 取证，并从已验证备份恢复；不得删除
checkpoint 或重新生成 HMAC 密钥来强行启动。

---

### 6.6 重载资源

```
POST /api/admin/reload
```

**说明：** 按数据库 `program_version` 目录重新加载受保护 JAR，而不是把
`resources/` 中的任意文件视为可加载资源。服务端会为每个 `Name`/`Version` 计算规范化
内容 SHA-256；内容被替换后会撤销旧租约，且旧 payload 摘要无法通过新会话注册或后续
心跳校验。未被数据库引用的 `.jar`/`.jar.part` 会在启动恢复时移入
`resources.quarantine/`；数据库引用文件缺失或身份不匹配时重载失败并保留上一份有效快照。

---

### 6.7 系统统计

```
GET /api/admin/stats
```

**成功响应 data：**
```json
{
  "userCount": 10,
  "programCount": 25,
  "licenseCount": 1000,
  "activeLicenses": 950,
  "bannedLicenses": 50,
  "banRecordCount": 30,
  "authLogCount": 50000,
  "versionCount": 60,
  "activeWebSessionCount": 4,
  "activeClientSessionCount": 12,
  "authRateLimitTrackedAddresses": 40,
  "authRateLimitRejectedCount": 7,
  "authRateLimitCapacityRejectedCount": 0,
  "heartbeatRateLimitTrackedAddresses": 12,
  "heartbeatRateLimitRejectedCount": 2,
  "heartbeatRateLimitCapacityRejectedCount": 0
}
```

限流统计仅为当前进程内的聚合计数，不包含 IP 或许可证；控制台 `refresh` 会清空
桶状态和这些计数。`CapacityRejectedCount` 非零表示地址桶达到硬容量，应结合防火墙
和入口流量监控排查扫描或伪造来源扩散。

---

### 6.8 获取全部验证日志

```
GET /api/admin/auth-logs?page=1&pageSize=20&programId=1&result=DELIVERY_FAILED
```

仅管理员可访问，支持按程序、许可证、IP、HWID、结果和时间范围筛选。

---

## 7. 数据模型

### WebUser

| 字段            | 类型     | 说明              |
|---------------|--------|-----------------|
| id            | long   | 用户ID            |
| username      | string | 用户名（去除首尾空格后 ASCII 大小写不敏感唯一） |
| role          | string | 角色：USER / ADMIN |
| maxPrograms   | int    | 允许创建的最大程序数      |
| status        | int    | 1=正常, 0=禁用      |
| createTime    | string | 创建时间            |
| lastLoginTime | string | 最后登录时间          |
| email         | string | 邮箱              |

> 注：password 字段不会在响应中返回

---

### Program

| 字段          | 类型     | 说明         |
|-------------|--------|------------|
| id          | long   | 程序ID       |
| userId      | long   | 所属用户ID     |
| name        | string | 程序名称       |
| description | string | 描述         |
| status      | int    | 1=正常, 0=禁用 |
| createTime  | string | 创建时间       |

---

### ProgramVersion

| 字段           | 类型     | 说明     |
|--------------|--------|--------|
| id           | long   | 版本ID   |
| programId    | long   | 所属程序ID |
| version      | string | 版本号    |
| fileName     | string | 文件名    |
| filePath     | string | 存储路径   |
| entryClass   | string | 入口类    |
| entryPoint   | string | 入口方法   |
| uploadTime   | string | 上传时间   |
| releaseNotes | string | 版本说明   |

---

### License

| 字段               | 类型     | 说明              |
|------------------|--------|-----------------|
| id               | long   | 授权ID            |
| code             | string | 授权码（唯一）         |
| programId        | long   | 所属程序ID          |
| userId           | long   | 创建者用户ID         |
| qq               | string | 关联QQ号（新数据为1-20位数字） |
| bindableIps      | int    | 可绑定IP数          |
| bindableHwids    | int    | 可绑定机器码数         |
| status           | int    | 1=正常, 0=封禁      |
| ips              | string | 已绑定IP列表（逗号分隔）   |
| hwids            | string | 已绑定机器码列表（逗号分隔）  |
| createTime       | string | 创建时间            |
| lastAuthTime     | string | 最后验证时间          |
| banReason        | string | 封禁原因            |
| notes            | string | 备注              |
| expirationDate   | string | 过期时间（null=永不过期） |
| maxDailyAuth     | int    | 每日最大验证次数（0=无限制） |
| lastModifiedTime | string | 最后修改时间          |

---

### AuthLog

| 字段        | 类型     | 说明    |
|-----------|--------|-------|
| id        | long   | 记录ID  |
| licenseId | long   | 授权码ID |
| code      | string | 授权码   |
| ip        | string | 验证IP  |
| hwid      | string | 机器码   |
| result    | string | 验证结果  |
| timestamp | string | 验证时间  |
| programId | long   | 程序ID  |
| userId    | long   | 用户ID  |

---

### BanRecord

| 字段             | 类型     | 说明                         |
|----------------|--------|----------------------------|
| id             | long   | 记录ID                       |
| type           | string | 封禁类型：IP / HWID / QQ / CODE |
| value          | string | 被封禁的值                      |
| reason         | string | 封禁原因                       |
| operatorId     | long   | 操作者ID                      |
| programId      | long   | 关联程序ID                     |
| createTime     | string | 封禁时间                       |
| expirationDate | string | 过期时间（null=永久）              |
| status         | int    | 1=生效, 0=暂停                 |

---

### OperationLog

密码、Cookie 和 Token 在写入前替换为 `***`；许可证、IP、HWID、QQ 与封禁值在
`detail` 中只保存稳定的不可逆 `ref:v1:` 引用。引用由服务端环境变量
`SKYLICENSE_OPERATION_LOG_HMAC_KEY` 通过域分离 HMAC-SHA-256 生成；该变量必须是
非零 64 位十六进制值。`ip` 字段同样只保存实际 TCP 对端的
不可逆引用，并且不会信任客户端可伪造的转发请求头；部署在反向代理后时该引用
对应代理地址。带 `@OpLog` 的写操作会在业务执行前先写入 `outcome=ATTEMPT` 预审计；
预审计无法持久化时接口返回 HTTP 503 且业务方法不会执行。业务完成后更新为
`SUCCESS` 或 `REJECTED`；完成更新失败时保留 `ATTEMPT`，服务 readiness 会降为 503。
拒绝事件只保存业务状态码或异常类型，不会保存异常消息。登录事件在会话建立前以
`userId=0`、`username=anonymous`
记录；用户名本身也只保存 HMAC 引用。登录来源不可信、CSRF 或跨来源拒绝会记录
为 `WEB_SECURITY_REJECT`，普通缺少会话的 401 不写入数据库以避免扫描流量膨胀。
拒绝事件按 HMAC 化来源和事件维度做有界的一分钟抑制；匿名登录审计被有意抑制时
仍会继续执行登录逻辑，不视为审计故障。

| 字段                | 类型          | 说明 |
|-------------------|-------------|------|
| id                | long        | 数据库日志 ID |
| eventId           | string      | UUID v4 事件 ID，用于跨页面/外部日志关联 |
| userId            | long        | 操作者 ID；匿名事件为 0 |
| username          | string/null | 操作者的不可逆 `ref:v1:` 引用；匿名事件为 `anonymous` |
| action            | string      | 操作类型 |
| target            | string      | 操作目标 |
| detail            | string/null | 已脱敏的操作详情 JSON |
| ip                | string/null | TCP 对端的不可逆引用；无来源时为 `unknown` |
| timestamp         | string      | 当前事件状态时间，规范 UTC `Instant`，例如 `2026-07-23T09:30:00Z` |
| outcome           | string      | `ATTEMPT` / `SUCCESS` / `REJECTED` / `LEGACY` |
| occurredAtMillis  | long        | 操作开始的 UTC epoch 毫秒 |
| completedAtMillis | long/null   | 完成的 UTC epoch 毫秒；`ATTEMPT` 时为 null |

`ATTEMPT` 表示业务调用已经开始但尚未完成，`SUCCESS` 表示业务方法正常返回，
`REJECTED` 表示业务被拒绝或抛出异常，`LEGACY` 只用于从旧数据库迁移且无法可靠判定
新状态语义的历史记录。服务端会验证每行形状、规范 UTC 时间、事件 ID 唯一性、行 MAC、
链 MAC 和认证 checkpoint；删除或修改任意保留行、头行或 checkpoint 都会使验证失败。

---

## 附录：首次管理员账号

首次启动且管理员不存在时自动创建：
- 用户名：`admin`
- 密码：必须通过 `SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD` 提供强随机值
- 创建成功后删除该环境变量，并按密钥管理流程保存或轮换管理员凭据
