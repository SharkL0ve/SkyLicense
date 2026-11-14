[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense 服务端

## 先从这里开始

本机完整体验请按 [根目录快速上手](../README.zh-CN.md#从这里开始基础可用版)：构建运行包、生成私有配置和本机证书、
启动服务端与内置 Web、上传 DemoApp、签发许可证，再运行真实客户端。不要把源码工作区当作正式运行目录。

远程部署的顺序是：构建 → 服务账号/TLS/固定密钥 → 配置 → 预检 → 启动 → 管理员 MFA → 上传程序 → 签发许可证 → [客户接入](../Client-Side/README.zh-CN.md)。

## 构建

准备完整 JDK 17 或 21，在仓库根目录执行：

```powershell
# Windows
.\gradlew.bat :test :Client-Side:test bootJar --no-daemon --warning-mode all
```

```sh
# Linux
./gradlew :test :Client-Side:test bootJar --no-daemon --warning-mode all
```

产物为 `build/libs/SkyLicense-Server.jar`。普通服务端构建不依赖 Rust 或 Node.js；JAR 会包含已提交的
src/main/resources/static 网站资源。修改前端时须先按 [Web 手册](../web/README.zh-CN.md) 构建并同步资源，再执行 bootJar。

## 运行目录及配置

使用专用低权限账号独占的独立目录：

```text
deployment-root/
  SkyLicense-Server.jar
  config.json
  certs/auth-chain.pem
  certs/auth-key.pem
  resources/
  secrets/                       # 或使用外部凭据系统
  web_magiclicense.db            # 首次成功启动创建
  logs/                          # 程序创建
```

以 [config.example.json](../deployment/config.example.json) 为起点，只在部署目录中复制为 config.json。
九个字段全部必需，未知或重复字段会拒绝。示例白名单对应基础 SDK；使用原生版时须添加实际发行 Build ID，并设置相容的最低 epoch。

| 字段 | 用途 |
| --- | --- |
| debug | 部署使用 false |
| authPort | 客户端 TLS/v4 TCP 认证端口，示例 13331 |
| webPort | HTTPS 后台/API 端口，示例 18443，不是明文 HTTP |
| authTlsCertificateChain | 叶证书在前的 PEM 证书链 |
| authTlsPrivateKey | 与证书匹配的 PEM 私钥 |
| authTlsServerName | 证书覆盖的实际域名/IP，不含协议、路径和端口 |
| minimumClientSecurityEpoch | 允许的最低 SDK epoch，正整数 |
| allowedClientBuildIds | 允许的 SDK Build ID 列表，每项 64 位十六进制 |
| allowedWebOrigins | 内置同源网站填写 []；分离前端填写精确 HTTPS Origin |

后台与认证端都要求 TLS 1.3，使用同一套证书。localhost 证书不能用于远程域名。
工作目录、资源、数据库及 sidecar、私钥和凭据必须仅所有者可访问；Windows 所有者必须是实际服务用户，不能是 Administrators 组。
不要添加宽松 ACL 绕过预检，按 [Linux](../deployment/linux/README.zh-CN.md) / [Windows](../deployment/windows/README.zh-CN.md) 指南准备服务账号。

## 固定凭据

推荐绝对路径的 _FILE 变量，同名直接变量不能与 _FILE 同时存在。
文件必须为仅所有者可访问的 UTF-8 普通文件，路径各级不允许链接或 reparse point；可有一个末尾换行。

| 变量 | 使用时机及内容 |
| --- | --- |
| SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE | 每次启动；固定、独立、非零 32 字节随机密钥的 64 位十六进制值 |
| SKYLICENSE_MFA_ENCRYPTION_KEY_FILE | 每次启动；另一份固定、独立的 64 位十六进制密钥 |
| SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE | 仅首次启动；12–128 位、至少三类字符的初始密码 |
| SKYLICENSE_TLS_KEY_PASSWORD_FILE | 仅加密 PEM 私钥需要 |
| SKYLICENSE_BACKUP_HMAC_KEY_FILE | 离线备份命令；独立、固定的 64 位十六进制密钥 |
| SKYLICENSE_OPERATION_LOG_MAX_ROWS_FILE | 可选；默认 500000，范围 10000–10000000 |

不能每次重启重新生成审计/MFA 密钥，须与数据库分开灾备。客户授权文件密钥属于客户端凭据，服务端启动不需要它。
生产凭据准备与服务管理器映射详见 [部署手册](../DEPLOYMENT.md)。

## 预检、启动、停止

使用相同服务账号、环境和部署工作目录。以下 PowerShell 示例仅用于已经准备好正式文件的服务账号：

```powershell
$env:SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE = 'C:\ProgramData\SkyLicense\secrets\operation-log-hmac.txt'
$env:SKYLICENSE_MFA_ENCRYPTION_KEY_FILE = 'C:\ProgramData\SkyLicense\secrets\mfa-encryption-key.txt'
# 仅首次启动；管理员存在后必须移除此映射：
$env:SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE = 'C:\ProgramData\SkyLicense\secrets\bootstrap-admin.txt'
java -jar .\SkyLicense-Server.jar --validate-config
# 看到 deployment_validation=ok 后再启动：
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -jar .\SkyLicense-Server.jar
```

Linux 用 export 设置绝对路径；systemd 推荐 LoadCredential，避免依赖交互终端环境。
预检不会创建缺失数据库。正式启动再次验证、持有 .skylicense.lock、创建/迁移 SQLite，认证监听器就绪后才开放 Web。
同一目录不能启动第二个服务进程。

浏览器打开 https://证书域名:webPort/，使用 admin 和初始密码登录，修改密码，然后在“账户安全”绑定 TOTP 并保存恢复码，重新登录。
下次启动前移除 bootstrap 映射和源文件；已有管理员时仍提供该凭据会被拒绝。建议验证第二个已启用 MFA 的管理员作为恢复通道。

前台窗口输入 stop；服务模式使用服务管理器停止。不要把强制杀进程作为正常升级方式。
控制台只提供 help、online、refresh、reload、stop，发证通过 Web/API 进行。

## 发布程序并验证

1. 按 [Web 手册](../web/README.zh-CN.md) 创建最终程序名，上传匹配的受保护 JAR。
2. [示例手册](../examples/basic-app/README.zh-CN.md) 说明 settings.yml、入口和依赖放置方式。
3. 为程序签发许可证，设置到期、绑定和每日额度，生成客户专属 license.dat。
4. 按 [SDK 手册](../Client-Side/README.zh-CN.md) 运行 BasicLauncher 或 NativeLauncher；ACCEPT 前 SDK 已执行入口并确认 ACK。
5. 后台验证日志最终为 OK，再封禁许可证，确认客户宿主停止受保护业务。

必须通过后台/API 上传，手工复制到 resources 不会建立版本目录。数据库目录为准，孤立 JAR 会隔离，引用文件缺失会使校验失败。
绑定和额度在资源释放时提交，入口或 ACK 失败可能记为 DELIVERY_UNCONFIRMED 且不退款。额度和绑定数不是同时在线数。

## 监控、备份及升级

使用正常 CA/主机名验证访问 https://域名:webPort/health/live 和 /health/ready。
认证监听器、数据库或审计持久化异常时 ready 返回 503。应用日志位于 logs/latest.log，时间为 UTC；操作日志页可校验审计链。

停服务后保留原审计/MFA 密钥，提供独立备份密钥，在部署目录执行：

```text
java -jar SkyLicense-Server.jar --create-backup <部署目录之外的私有目录>/backup.skybackup
java -jar SkyLicense-Server.jar --verify-backup <备份路径>/backup.skybackup
java -jar SkyLicense-Server.jar --extract-backup <备份路径>/backup.skybackup <全新恢复目录>
```

替换占位路径。归档有认证但没有加密，须放在加密存储中；不含 TLS 私钥和环境凭据，需独立恢复。
恢复到新目录、补齐密钥和权限、通过预检后再切换服务。升级保留业务库、密钥和资源目录，数据库迁移不能替代备份。

问题排查：[SDK 错误表](../Client-Side/README.zh-CN.md#故障排查)、[Web 排查](../web/README.zh-CN.md#故障排查)、
[API 参考](../API-DOC.md)、[验证报告](../VALIDATION.md)。
