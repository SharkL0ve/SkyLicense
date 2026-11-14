[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense Web 管理后台

## 使用后台

正常安装不需要单独启动前端：SkyLicense-Server.jar 已在同一 HTTPS 站点提供本网站与 /api。
按 [根目录流程](../README.zh-CN.md) 初始化后，打开 https://localhost:18443/。
没有公开注册页，也没有通用默认密码；首次账号是 admin，密码由你在初始化时设置。

1. 通过账户菜单修改初始密码，重新登录。
2. 进入“账户安全”，用当前密码开启验证器绑定，确认 TOTP，保存只显示一次的恢复码。
3. 再次登录。管理员未启用 MFA 时只允许账户安全相关操作，业务接口 403 属于预期。
4. 按需要创建普通用户，确定最终程序名，上传匹配 JAR/版本，再为该程序签发许可证。
5. 给客户生成 license.dat，按 [SDK 指南](../Client-Side/README.zh-CN.md) 启动；Web 本身不运行客户受保护代码。
6. 验证日志应最终为 OK，测试封禁/解封/解绑，并在操作日志页检查审计完整性。

| 页面 | 用途 |
| --- | --- |
| /security | 验证器、恢复码及账户安全 |
| /programs | 所属程序、版本及许可证签发 |
| /licenses/:code | 许可证策略、绑定和历史 |
| /bans、/auth-logs | 所属程序封禁和验证记录 |
| /admin/users、/admin/programs、/admin/licenses | 管理员跨用户管理 |
| /admin/operations | 脱敏操作日志和审计链校验 |

角色和归属由后端校验，不是仅隐藏菜单。保留第二个已验证 MFA 管理员；另一管理员重新验证凭据后可重置目标 MFA，但不能重置自己。

## 构建并嵌入服务端

要求 Node.js ^20.19.0 或 >=22.12.0，npm 10+，包管理器固定为 npm 10.9.2。在 web 目录执行：

```sh
npm ci --ignore-scripts
npm run typecheck
npm run build
npm audit --audit-level=high
```

build 已包含类型检查，产物为 web/dist。npm 是唯一包管理器，.npmrc 禁用了依赖生命周期脚本，不要新增其他锁文件。
上次验收记录有 5 项开发工具中风险告警；每次交付重新审计，不要把历史数量当成永久安全保证。

然后回到仓库根目录，把 dist 完整镜像到 src/main/resources/static，再构建服务端。
以下命令会清理目标中的旧生成资源，必须确认路径，不能指向 runtime、客户目录或其他业务数据。

```powershell
# Windows，仓库根目录：
$root = (Resolve-Path .).Path
if (-not (Test-Path .\settings.gradle) -or -not (Test-Path .\web\dist\index.html)) { throw 'Wrong root or missing frontend build' }
$source = Join-Path $root 'web\dist'
$target = Join-Path $root 'src\main\resources\static'
robocopy $source $target /MIR /R:1 /W:1
if ($LASTEXITCODE -ge 8) { throw 'Static asset synchronization failed' }
.\gradlew.bat bootJar --no-daemon
```

```sh
# Linux，仓库根目录，预先安装 rsync：
(
  set -eu
  test -f settings.gradle && test -f web/dist/index.html
  rsync -a --delete web/dist/ src/main/resources/static/
  ./gradlew bootJar --no-daemon
)
```

只执行 Vite build 不会更新服务端 JAR，必须部署重建后的 JAR、重启服务、刷新浏览器。
内置后台处理 SPA 路由；独立静态站点需配置 history 回退，但不能把 API 错误或缺失 JS 也回退成 index.html。

## 使用真实后端进行 HTTPS 开发

当前默认 npm run dev 使用 HTTP 3000，/api 代理至 https://localhost:8080，且关闭了上游证书验证。
它不是本机包默认 18443 的现成登录配置，也不能用于生产。建议用以下本地覆盖配置，保留上游 TLS 校验：

1. 按 [运行包手册](../deployment/basic/README.zh-CN.md) 启动本机服务，或使用单独开发服务端。
2. 在该服务端 config.json 的 allowedWebOrigins 中精确加入 https://localhost:3000，保留其他必需字段，重启服务。
   这是开发站点 Origin；生产内置同源后台仍保持 []。
3. 新建被 Git 忽略的 web/vite.local.config.ts，内容如下。私钥不能放进 public、dist 或源码仓库。

```ts
import { readFileSync } from 'node:fs'
import { Agent } from 'node:https'
import { mergeConfig } from 'vite'
import base from './vite.config'

function required(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`Missing ${name}`)
  return value
}

export default mergeConfig(base, {
  server: {
    host: 'localhost', port: 3000, strictPort: true,
    https: {
      key: readFileSync(required('SKYLICENSE_WEB_DEV_KEY_FILE')),
      cert: readFileSync(required('SKYLICENSE_WEB_DEV_CERT_FILE')),
      minVersion: 'TLSv1.3',
    },
    proxy: {
      '/api': {
        target: process.env.SKYLICENSE_WEB_DEV_API_ORIGIN || 'https://localhost:18443',
        changeOrigin: true, secure: true,
        agent: new Agent({
          ca: readFileSync(required('SKYLICENSE_WEB_DEV_CA_FILE')),
          minVersion: 'TLSv1.3',
        }),
      },
    },
  },
})
```

4. 在专用开发终端中设置本机测试证书/私钥及后端 CA 的绝对路径，然后从 web 运行：

```powershell
$env:SKYLICENSE_WEB_DEV_KEY_FILE = 'C:\SkyLicenseLocal\SkyLicense-Basic\runtime\certs\auth-key.pem'
$env:SKYLICENSE_WEB_DEV_CERT_FILE = 'C:\SkyLicenseLocal\SkyLicense-Basic\runtime\certs\auth-chain.pem'
$env:SKYLICENSE_WEB_DEV_CA_FILE = $env:SKYLICENSE_WEB_DEV_CERT_FILE
$env:SKYLICENSE_WEB_DEV_API_ORIGIN = 'https://localhost:18443'
npm run dev -- --config vite.local.config.ts
```

Linux 用 export 设置相同变量。只能使用开发证书，不能把生产私钥交给 Vite。
打开 https://localhost:3000，仅信任自己的开发证书，再正常登录/绑定 MFA。
不设置 VITE_API_BASE_URL，使请求走 /api 代理；以上非 VITE_ 变量只在开发服务进程读取。
npm run preview 同样不是已配置好的认证后台或生产服务器。

## 前后端分离及会话规则

优先内置同源后台，或 HTTPS 同源反向代理。必须跨 Origin 时，在构建前设置公开变量
VITE_API_BASE_URL=https://api.example.com/api，并把前端精确 HTTPS Origin 加入服务端 allowedWebOrigins。
构建完成后再修改 .env 不会改变既有 JS。VITE_ 变量会进入浏览器，严禁放密钥。

API 使用 Secure、HttpOnly 的 __Host-skylicense_session Cookie，不使用 localStorage Bearer Token。
Axios 携带凭据；CSRF 仅存内存，通过 /api/auth/session 恢复，写请求携带 X-CSRF-Token。
不能关闭 Origin/CSRF 来绕过部署问题。跨站 Cookie 可能被浏览器隐私策略拦截，同源可避免该问题。
独立静态站点还需自己的 CSP/安全响应头，后端 CSP 不会保护另一个网站。
反向代理应保留 Origin、CSRF 和 Set-Cookie；如果后端看到的域名/端口不同，应准确放行外部网站 Origin。

## 故障排查

| 现象 | 检查 |
| --- | --- |
| 登录 403 | HTTPS Origin 白名单、代理目标、管理员 MFA 限制 |
| 反复回到登录页/没有 Cookie | HTTPS、主机名一致性、Secure 和第三方 Cookie 策略 |
| 改密码/MFA 后 401 | 旧会话已撤销，重新登录 |
| API 格式无法识别 | API 基址包含 /api，代理不能返回 index.html |
| 上传被拒绝 | 64 MiB、名称/版本匹配、settings.yml 和公开静态入口 |
| 页面仍旧 | 完整同步 dist、重新打包部署 JAR、重启并刷新缓存 |
| 刷新详情页 404 | 独立静态站点的 SPA history 回退 |
| 代理证书错误 | 后端 SAN/域名、CA、有效期和端口，不要关闭 secure |

更多：[服务端](../src/README.zh-CN.md)、[API 参考](../API-DOC.md)、[验证报告](../VALIDATION.md)。
