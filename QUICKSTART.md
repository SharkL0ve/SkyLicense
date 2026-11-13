# SkyLicense 实际使用运行手册

当前可直接运行的 **Java 基础版** 请先使用 [README 顶部流程](README.md) 或
[基础版逐步使用手册](deployment/basic/README.md)。它通过 `basicReleaseZip` 打包，
不依赖 DLL/SO；受保护程序认证、入口、ACK、心跳和在线撤销已做真实验证。
下面保留的是原生增强版发布与部署规范，需要另外恢复匹配的 v4 原生源码及签名材料。
本仓库 native/ 是旧 v2 客户端源码，不包含下文提及的 release-native、sign_artifact 或 verify_artifact 实现，不能按这些规范直接发布。

这份手册是一次完整交付的执行顺序。它假定服务端、Vue 前端和 Java SDK
已经从同一批源码构建；协议为 v4，认证和后台都只接受 TLS 1.3。

## 0. 先确认当前目录能否直接运行

当前源码目录默认不能直接用于生产：真实 config.json、生产 TLS 证书、原生库和凭据均不随源码提交。
源码工作区也不是独立的 owner-only 部署目录。基础版请使用 README 的初始化脚本生成本地测试部署；
原生增强版必须先恢复匹配源码、完成第 1 节的发布流程，再按第 3–4 节建立独立部署目录并配置凭据。

## 1. 生成一次正式发布身份

在离线密钥管理器中分别生成并保存：

- TLS 私钥和公共 CA 证书链；证书 SAN 必须包含客户端实际使用的主机名。
- Ed25519 清单签名私钥；只把公钥放入构建环境和服务端配置。
- 每个发布唯一的 32 字节 Build ID。
- 当前 security epoch；修改 HWID 或安全策略时递增。
- Windows Authenticode PFX、口令和证书 DER 的 SHA-256。

先计算 TLS 叶证书 DER 的 SHA-256，作为原生构建的
`SKYLICENSE_CERT_SHA256`。证书轮换时，先把下一张证书放到
`SKYLICENSE_CERT_SHA256_NEXT` 并发布客户端，再切换服务端证书，最后发布
只保留新主 Pin 的清理版本。标准 CA 链和主机名校验始终执行，Pin 不能替代它们。

生产原生库必须分别在 Windows MSVC 和 Linux GNU runner 构建，Windows 先做
Authenticode，Linux 先做最终 strip，再生成 `.integrity`。使用客户端仓库的
`release-native` 工作流发布四个资产；随后使用本仓库的
`package-sdk-release` 下载并验证同一 Build ID、epoch、公钥和校验和，发布
`SkyLicense.jar`。不要从开发机目录、普通 Actions artifact 或当前被忽略的
CI DLL/SO 打包。

## 2. 构建前端和服务端

前端要求 Node.js `^20.19.0` 或 `>=22.12.0`：

```powershell
cd F:\Code\Source\SkyLicense\web
npm ci --ignore-scripts
npm run typecheck
npm run build
```

将 web/dist 完整镜像到同一仓库根目录的 src/main/resources/static/，
删除旧的内容哈希文件。服务端要求 Java 17：

```powershell
cd F:\Code\Source\SkyLicense
.\gradlew.bat clean test :Client-Side:test bootJar --no-daemon --warning-mode all
```

正式服务端文件是 `build/libs/SkyLicense-Server.jar`。正式 SDK 只使用第 1 节
Release 中的 `SkyLicense.jar`，不要把 `:Client-Side:jar` 的本地临时结果当成生产包。

## 3. 准备服务端目录

从一个全新的 owner-only 目录启动，至少包含：

```text
SkyLicense-Server.jar
config.json
certs/auth-chain.pem
certs/auth-key.pem
resources/
```

`resources/` 只是资源文件存放区，真正决定哪些 JAR 可以加载的是数据库中的
`program_version` 目录记录。不要手工把 JAR 放进该目录后期待它被自动启用；启动时
未被数据库引用的 `.jar`/`.jar.part` 会移入 `resources.quarantine/`，而数据库引用的
文件缺失或 `Name/Version` 不匹配会使预检/启动失败。

全新安装可以没有 `web_magiclicense.db`：只读预检通过后，服务会在第一次正式启动时
创建并收紧其权限。升级或恢复必须保留已有数据库，以及当时存在的
`web_magiclicense.db-wal`/`web_magiclicense.db-shm` sidecar。

`config.json` 的关键字段示例：

```json
{
  "debug": false,
  "authPort": 13331,
  "webPort": 8080,
  "authTlsCertificateChain": "certs/auth-chain.pem",
  "authTlsPrivateKey": "certs/auth-key.pem",
  "authTlsServerName": "license.example.com",
  "minimumClientSecurityEpoch": 1,
  "allowedClientBuildIds": ["<正式 SDK 输出的 64 位 Build ID>"],
  "allowedWebOrigins": []
}
```

同源内置前端保持 `allowedWebOrigins: []`。如果把前端单独放到别的站点，填写
完整且精确的 `https://host[:port]` Origin，不要填写路径、通配符或凭据。
`authTlsServerName` 只写裸 DNS 名称或数字 IP，不写 `https://`、端口或路径。

## 4. 写入服务端凭据并预检

推荐用 owner-only 文件而不是把值写进命令行或仓库。支持的文件变量如下：

```text
SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE
SKYLICENSE_MFA_ENCRYPTION_KEY_FILE             # 固定的32字节十六进制密钥
SKYLICENSE_TLS_KEY_PASSWORD_FILE              # 加密 PEM 才需要
SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE      # 仅首次启动
SKYLICENSE_OPERATION_LOG_MAX_ROWS_FILE        # 可选
SKYLICENSE_BACKUP_HMAC_KEY_FILE               # 仅备份命令
```

审计 HMAC 和 MFA 加密密钥分别使用独立的非零 64 位十六进制随机值，例如分别执行
`openssl rand -hex 32`。同名直接变量和 `_FILE` 不能同时设置。文件必须是绝对路径、普通非符号链接文件，
路径各级不能是 reparse point，且只能由所有者访问；内容为严格 UTF-8，允许一个
末尾换行，内部不能有换行或 NUL。

Linux 使用仓库 `deployment/linux/` 的 `LoadCredential` 模板。Windows 使用
`deployment/windows/` 的 WinSW 模板和 ACL 安装脚本。首次启动必须提供至少 12
字符、至少三类字符的 bootstrap 密码；管理员创建后删除该映射和文件。审计 HMAC
必须固定保存，不能每次随机生成，否则旧审计引用无法关联。MFA 密钥也必须固定并纳入
灾备密钥清单；丢失它会使数据库中的现有 TOTP 种子无法解密。

在与服务进程完全相同的工作目录、账号和凭据下运行只读预检：

```text
java -jar SkyLicense-Server.jar --validate-config
```

看到 `deployment_validation=ok` 后才启动服务。预检会检查证书链、私钥匹配、SAN、
TLS 1.3、SQLite、数据库目录引用的资源 JAR 和权限；不会创建缺失的数据库/资源目录。正式启动会再做
一次相同检查，并持有 `.skylicense.lock`，因此同一目录不能运行第二个进程。

## 5. 启动并登录后台

Linux：

```bash
sudo systemctl enable --now skylicense.service
```

Windows：使用安装脚本配置服务账号后启动 `SkyLicense` 服务。首次登录地址是
`https://license.example.com:8080/`（端口按配置调整），账号固定为 `admin`，密码
就是 bootstrap 文件内容。未启用 MFA 的管理员会被强制停留在“账户安全”，服务端只
允许读取本人会话/MFA 状态、修改密码、完成 enrollment 或登出，其他 API 均返回 403。
先立即修改 bootstrap 密码并重新登录，再在“账户安全”输入
当前密码、扫描 QR 或录入手动密钥、提交 6 位验证码，并把只显示一次的恢复码保存到
密码管理器。启用或重建恢复码后当前会话会失效，必须重新登录。浏览器使用 HttpOnly
会话 Cookie，所有写操作由前端自动携带会话绑定的 CSRF Token。

立即创建第二个 `ADMIN` 账号，并让该账号登录、修改初始密码和启用 MFA。管理员不能
自行禁用 MFA；管理员详情页的“管理员重置 MFA”只能由另一名
管理员使用自己的当前密码和 TOTP/恢复码执行，不能重置自己；目标用户的会话和挑战会被
撤销。若唯一管理员同时丢失验证器和全部恢复码，当前系统没有绕过 MFA 的安全自助流程，
应由另一名管理员恢复，不能直接编辑 SQLite。

## 6. 在后台创建可验证程序

1. 管理员在“用户管理”创建普通用户并设置最大程序数；也可以直接由管理员代管程序。
2. 在“程序管理”创建程序，记下最终 `name`。上传第一个版本后程序名不能再改。
3. 准备受保护 JAR。根目录必须有 `settings.yml`，文件不超过 64 MiB，入口类必须
   存在并提供无参数公开静态方法。
4. `settings.yml` 最小示例：

   ```yaml
   Name: MyPlugin
   Version: 1.0.0
   EntryClass: com.example.protected.Bootstrap
   EntryPoint: start
   InfPort: false
   KeepClasses:
     - "com/example/reflective/[\\s\\S]*"
   ```

   `Name`/`Version` 必须与后台程序和客户端调用参数完全一致；`EntryClass` 可使用点分
   类名，服务端会规范化为 JVM 斜杠形式。`KeepClasses` 正则按斜杠类名匹配，其中的类
   仍会加密传输，但跳过方法改写，适合反射/序列化框架。
5. 在程序详情上传 JAR。服务端会解析入口、扫描重复版本，并提交资源文件及数据库版本
   目录记录；失败时先看页面提示和管理员验证日志，不要反复上传同一个坏包。

## 7. 创建和交付许可证

在程序详情或管理员“许可证管理”中创建许可证：

- `bindableIps=0` 表示不限制且不记录 IP；大于零表示最多绑定的 IP 数。
- `bindableHwids=0` 表示不限制机器；大于零表示最多绑定的 HWID 数。
- `expirationDate` 留空为永久，否则使用 `yyyy-MM-dd-HH:mm`。
- `maxDailyAuth=0` 表示不限制；大于零按服务端自然日统计初次资源释放次数。
- `QQ` 和备注是业务字段，不能替代密码或部署密钥。

复制刚创建的授权码，只通过受控交付渠道发送给客户。每个客户必须使用独立的
`SKYLICENSE_LICENSE_FILE_SECRET`，建议写入客户运行账号 owner-only 的
`SKYLICENSE_LICENSE_FILE_SECRET_FILE` 文件。服务端审计日志不会保存授权码原文，只保存
不可逆引用。

## 8. 客户端接入和首次启动

使用正式 `SkyLicense.jar` 和客户宿主程序实现 `PluginProxy`。宿主只放启动器，
不要把受保护入口类再次打进宿主 JAR：

```java
SkyLicense client = new SkyLicense(new LicenseBootstrap());
Response result = client.authenticate(
        "license.example.com:13331", "MyPlugin", "1.0.0");
if (result != Response.ACCEPT) {
    throw new IllegalStateException("license failure: " + result);
}
```

`LicenseBootstrap` 必须实现 `getDataFolder()`、`info()`、`disablePlugin()`、
`getResource()`、`getResourceType()` 和 `isPrimaryThread()`。数据目录只能由客户运行账号
访问；SDK 会把原生库解压到其 `authlib` 子目录并验证清单。目标仅支持 Windows/Linux
x86-64；32 位 JVM 和 macOS 不在正式 SDK 范围内。

先将授权码交给交互式工具生成 `license.dat`，授权码不会出现在命令行：

```text
java -cp SkyLicense.jar cn.sky.license.LicenseFileTool ./license.dat
```

工具会从标准输入隐藏读取授权码，并使用当前
`SKYLICENSE_LICENSE_FILE_SECRET[_FILE]` 生成 `SKYLIC03` 文件。把 `license.dat` 放在
客户宿主的 classpath 根目录；启动时必须解析到同一个部署密钥：

```text
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading \
  -cp ".:customer-app.jar:SkyLicense.jar" LicenseBootstrap
```

Windows classpath 分隔符改为 `;`。`ACCEPT` 表示资源解密、入口返回、心跳和服务端
ACK 全部完成；宿主不要再次调用入口。`BUSY`、连接超时等 `Response.retry()` 为真的
结果可以有限重试。绑定、封禁、过期、每日额度、入口异常、撤销和
`DELIVERY_ACK_ERROR` 必须修复原因并重启 JVM，不能在同一进程重复认证。

## 9. 日常管理和故障定位

- 监控使用 `GET /health/live` 判断 Web 进程存活，使用 `GET /health/ready` 判断服务是否
  已完成启动且原生 TLS 监听器、SQLite 和操作审计持久化均可用。两个端点不需要会话，只返回
  `{"status":"UP"}` 或 `{"status":"DOWN"}`，并禁止缓存；就绪失败返回 HTTP 503。
  探针必须正常校验证书和主机名，不能使用 `curl -k` 绕过 TLS。
- 程序/版本变更后使用管理员“重载”。重载只读取数据库目录引用的 JAR；不要修改同名
  同版本文件后继续使用旧租约。未被数据库引用的孤立 JAR 会在启动恢复阶段移入
  `resources.quarantine/`，不会被加载或纳入备份；引用文件缺失时重载保持旧快照并报错。
- 许可证详情可解绑 IP/HWID、封禁/解封；解绑不会退回已经释放的每日额度。
- “验证日志”按程序、许可证、IP、HWID、结果和时间筛选。`DELIVERY_FAILED` 表示资源
  尚未释放，通常可在修复后重试；`DELIVERY_UNCONFIRMED` 表示资源已释放，绑定和额度
  保留，必须新进程启动。
- 管理员“操作日志”页会显示审计链完整性状态；上线后、恢复后以及安全事件调查前应
  点击“重新校验”。失败时 `/health/ready` 会返回 503，应立即停止后台写操作并保留
  数据库、WAL/SHM sidecar 和日志取证，不能删除 checkpoint 或更换审计 HMAC 强行启动。
- 心跳租约约 90 秒；管理员禁用用户/程序、封禁许可证或收紧 Build ID/epoch 后，在线
  客户端会在下一次心跳收到撤销。
- 后台 401 表示会话失效，应重新登录；未启用 MFA 的管理员收到 403 时应进入“账户安全”
  完成 enrollment。其他 403 按权限或 Origin/CSRF 问题排查，不要手工复制 Cookie 或
  CSRF 到 Web Storage。
- 带审计注解的后台写操作会先写入 `ATTEMPT`；若审计数据库不可写，接口返回 503
  且不会修改许可证/程序。完成阶段故障会留下 `ATTEMPT`，此时先恢复审计写入并
  确认 `/health/ready` 返回 200，再重试业务；匿名登录审计的有意限流不会阻止登录。
- 当前数据库 schema 为 v9。服务端会在写入时保护用户、程序、版本、许可证、封禁、MFA
  挑战和会话之间的关系，并在启动/readiness 扫描孤儿行。登录失败限流状态保存在
  SQLite 中，重启不会清除账号、来源地址或 MFA 挑战的锁定窗口。不要直接用 SQLite
  修改这些关系；发现关系校验失败时保留数据库及 WAL/SHM，从已验证备份恢复后再运行
  预检。未知授权码的失败日志使用 `0/0/0` 哨兵，许可证删除后历史验证日志可以保留。
- 已启用 MFA 的账号先校验密码，再在登录页提交 6 位 TOTP 或一条未使用的恢复码；挑战
  有效期 5 分钟且最多失败 5 次。密码正确但第二因素失败不会建立 Web 会话，恢复码每次
  使用后立即作废。
- MFA enrollment、恢复码重建、普通用户禁用 MFA 和管理员重置也按账号独立限流：连续 5 次凭据
  失败后锁定 5 分钟，重启服务不会清除锁定；成功完成管理操作后计数清零。
- 应用日志写入 `logs/latest.log`，按 UTC 时间、每天或 50 MiB 滚动。归档在滚动时按
  30 天、200 个文件或累计 2 GiB 任一上限清理；仍需监控部署卷可用空间并将审计日志
  外送到独立、访问受控的日志平台。

## 10. 备份和恢复

备份密钥独立于审计 HMAC、TLS 私钥和客户授权文件密钥。服务停止后执行：

```text
java -jar SkyLicense-Server.jar --create-backup /secure-backups/skylicense.skybackup
java -jar SkyLicense-Server.jar --verify-backup /secure-backups/skylicense.skybackup
```

归档包含数据库、配置、数据库目录引用的受保护资源和证书链，不包含孤立 JAR、TLS 私钥
或任何环境秘密。MFA 加密密钥、审计 HMAC 和备份 HMAC 必须由凭据系统单独保存；目标必须
在部署目录之外。恢复到全新目录：

```text
java -jar SkyLicense-Server.jar --extract-backup \
  /secure-backups/skylicense.skybackup /restore/new-deployment
```

再独立恢复私钥和 `_FILE` 凭据、修复 owner-only 权限、运行 `--validate-config`，通过后
才切换服务。Linux 定时模板会自动停服务、创建并验证归档、按原运行状态恢复；Windows
脚本要求由专用服务/备份账号执行。至少每季度做一次隔离主机恢复演练。

更多接口字段、状态码、权限和运维命令见 [DEPLOYMENT.md](DEPLOYMENT.md) 与
[API-DOC.md](API-DOC.md)。
