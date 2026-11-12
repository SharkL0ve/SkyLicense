# SkyLicense 部署与使用手册

本文档描述协议 v4、TLS 1.3 和 Web 管理后台统一后的生产流程。旧控制台发证、明文 HTTP、旧 WebSocket 远控和协议 v1-v3 均不再可用。

## 1. 系统组成

- `SkyLicense-Server.jar`：HTTPS 管理后台、Web API、SQLite 数据库、TLS 原生认证和资源下发。
- `skylicense`：Vue 管理前端，生产构建后嵌入服务端 JAR，推荐与 API 同源部署。
- `Client-Side`：Java SDK，内含 Windows/Linux x86-64 原生库和签名清单。
- Rust 原生客户端：负责 TLS、证书 Pin、Build ID、HWID、挑战握手、资源解密、心跳和运行时保护。

## 2. 生产发布顺序

1. 为管理域名准备公共 CA 签发的证书，证书 SAN 必须包含客户端实际连接的 DNS 名称。
2. 将叶证书和中间链保存为 `certs/auth-chain.pem`，私钥保存为 `certs/auth-key.pem`。
3. 计算叶证书 DER 的 SHA-256，作为 Rust 构建时的 `SKYLICENSE_CERT_SHA256`；轮换窗口内同时提供下一张证书的 `SKYLICENSE_CERT_SHA256_NEXT`。
4. 生成并离线保存 Ed25519 清单私钥；将公开密钥编译进所有 Balanced/Strict 原生库。
5. 每次安全发布生成非零 256 位 Build ID；重大安全策略或 HWID 算法变化时递增 security epoch。
6. 分别在原生 Windows MSVC 和 Linux GNU 环境构建。Windows 先做 Authenticode，Linux 先做最终 strip，再生成 `.integrity`。
7. 使用 `verify_artifact` 以及对应的 PE/ELF 硬化脚本，验证平台、架构、epoch、Build ID、库 SHA-256 和 Ed25519 签名。
8. 将 DLL、SO 和两个 160 字节清单放入 `Client-Side/src/main/resources`，使用同一组发布环境变量运行 `:Client-Side:verifyNativeReleaseArtifacts` 和 `:Client-Side:jar`。
9. 将任务输出的所有 Build ID 加入服务端 `allowedClientBuildIds`，旧版本下线后再移除旧 ID。

禁止将 CI 中的固定测试 Build ID、测试签名私钥或虚假证书 Pin 用于生产。SDK
打包默认使用 `production` 通道并拒绝仓库 CI 的固定测试身份；只有明确设置
`SKYLICENSE_ARTIFACT_CHANNEL=ci-test` 才允许测试身份通过验证。
`sign_artifact` 和 `verify_artifact` 在运行时会再次执行该通道门禁，并要求运行时
公钥、最低/当前 epoch 和 Build ID 与工具编译时的身份完全一致。签名私钥种子不能
为全零，且必须派生出声明的公钥。每组正式发布身份都必须重新构建发布工具，禁止仅
修改预编译签名器的环境变量后继续签名。
当前协议 v4 强制要求加载完成 ACK；未实现 `SKDA` ACK 的旧 v4 客户端会
在资源发送后超时并记为 `DELIVERY_UNCONFIRMED`，且已经释放的资源仍占用绑定和
额度。升级服务端时只应放行已经
实现 ACK 的新 Build ID，不能继续白名单旧构建。

原生发布工具和 SDK 打包门禁使用同一组非测试环境变量：

```text
SKYLICENSE_MANIFEST_PUBLIC_KEY=<正式Ed25519公钥>
SKYLICENSE_MIN_SECURITY_EPOCH=<服务端接受的最低epoch>
SKYLICENSE_SECURITY_EPOCH=<本次构建epoch>
SKYLICENSE_BUILD_ID=<本次构建64位十六进制ID>
SKYLICENSE_ARTIFACT_CHANNEL=production
```

完成 Authenticode 或最终 strip 后，先签清单，再做完整验证：

```text
cargo build --release --locked --lib --bin sign_artifact --bin verify_artifact
cargo run --release --locked --bin sign_artifact -- <最终DLL或SO>
cargo run --release --locked --bin verify_artifact -- <最终DLL或SO>
```

上述构建、签名和验证命令必须在同一个发布身份环境中执行；任一变量发生变化后都应
重新执行 `cargo build --release`，运行时门禁会拒绝身份不一致的旧工具。

Windows 再运行 `verify-pe-hardening.ps1 -RequireAuthenticode -RequireIntegrityManifest`；
Linux 运行 `verify-elf-hardening.sh <SO> --require-integrity-manifest`。两个脚本在要求
清单时会调用同一个密码学验证器，而不是只检查 160 字节长度。SDK 验证任务会输出
`allowed_client_build_ids=["..."]`，应原样同步到 `config.json`。

SDK 打包还会通过独立的 Java 二进制解析器重复检查原生产物。Windows 必须是
x86-64 PE32+ DLL，包含 `HIGH_ENTROPY_VA`、`DYNAMIC_BASE`、`NX_COMPAT`、
`GUARD_CF`，且 Load Configuration Directory 必须实际映射到文件节；Linux 必须是
x86-64 ELF64 shared object，包含 `GNU_RELRO`、不可执行 `GNU_STACK`、
`BIND_NOW`，且不得出现 RWX `LOAD`。该解析器具有截断、错误架构、缺失标志、
可执行栈、RWX 和缺失 `BIND_NOW` 的负向测试。Gradle、Rust 脚本和 Authenticode
验证必须全部通过，任一项不能互相替代。

### 2.1 跨仓库自动发布

原生二进制不提交到服务端仓库。普通服务端 CI 会明确验证缺少四个原生产物时
SDK 打包必须失败；正式交付使用两阶段受保护工作流：

1. 在 `MagicLicense-Client` 仓库配置 `native-production` Environment。变量包括
   `SKYLICENSE_MANIFEST_PUBLIC_KEY`、`SKYLICENSE_CERT_SHA256`、可选的
   `SKYLICENSE_CERT_SHA256_NEXT`、代码签名证书 DER 的
   `WINDOWS_CODESIGN_CERT_SHA256` 和 `WINDOWS_CODESIGN_TIMESTAMP_URL`；Secret 包括
   `SKYLICENSE_MANIFEST_PRIVATE_KEY`、`WINDOWS_CODESIGN_PFX_BASE64` 和
   `WINDOWS_CODESIGN_PASSWORD`。Environment 应启用 required reviewers。
2. 手动运行 `release-native`，输入从未使用过的 release tag、随机 Build ID、当前
   epoch 和最低 epoch。Windows/Linux job 使用同一身份分别构建，Windows 先做
   Authenticode，Linux 先做最终 strip，再签 `.integrity`、运行硬化检查和真实 JVM
   加载检查。全部通过后发布不复用 tag 的 GitHub Release，并附带校验和与公开元数据；
   原生仓库应同时启用 GitHub immutable releases 设置。
3. 在服务端仓库配置 `production-sdk` Environment，至少设置同一个
   `SKYLICENSE_MANIFEST_PUBLIC_KEY` 和 `WINDOWS_CODESIGN_CERT_SHA256`。原生仓库为私有仓库时，再配置只读细粒度 Secret
   `NATIVE_RELEASE_READ_TOKEN`；公开仓库可使用默认 token。该 Environment 同样应
   启用 required reviewers。
4. 手动运行 `package-sdk-release`，输入原生 release tag 和完全相同的 Build ID、
   当前 epoch、最低 epoch，并指定一个从未使用过的 SDK release tag。工作流从原生
   Release 下载四个精确文件、公开元数据和校验和，
   在 Windows runner 上验证资产集合、代码签名证书指纹、PE/ELF 加固、Ed25519
   清单、哈希和最终 JAR 内容，生成仅对应交付 JAR 的 `SHA256SUMS`、公开
   `sdk-release.json` 和 GitHub build provenance，最后创建不可覆盖的正式 SDK
   GitHub Release。服务端仓库同样应启用 GitHub immutable releases。

禁止从普通 Actions 临时 artifact、开发机目录或未发布的草稿替代上述 Release。
GitHub Release tag 已存在时原生工作流会拒绝覆盖；需要修复时必须使用新 Build ID
和新 tag 重新发布。SDK tag 已存在时打包工作流也会拒绝覆盖；Actions 临时 artifact
只用于工作流内诊断，客户交付必须来自正式 SDK Release 并校验其 provenance 与
`SHA256SUMS`。

## 3. 服务端配置

推荐配置：

```json
{
  "debug": false,
  "authPort": 13331,
  "authTlsCertificateChain": "certs/auth-chain.pem",
  "authTlsPrivateKey": "certs/auth-key.pem",
  "authTlsServerName": "license.example.com",
  "minimumClientSecurityEpoch": 1,
  "allowedClientBuildIds": ["<64位十六进制Build ID>"],
  "webPort": 8080,
  "allowedWebOrigins": []
}
```

生产环境通过进程环境提供：

```text
SKYLICENSE_TLS_KEY_PASSWORD=<仅加密PEM私钥需要>
SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD=<仅首次创建admin时需要>
SKYLICENSE_OPERATION_LOG_HMAC_KEY=<openssl rand -hex 32>
SKYLICENSE_MFA_ENCRYPTION_KEY=<独立的openssl rand -hex 32>
SKYLICENSE_OPERATION_LOG_MAX_ROWS=<可选，默认500000，范围10000-10000000>
```

以上每个变量都支持互斥的 `_FILE` 形式；备份密钥和客户授权文件密钥也一样：

```text
SKYLICENSE_TLS_KEY_PASSWORD_FILE=<绝对路径，可选>
SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE=<绝对路径，仅首次启动>
SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE=<绝对路径，必需>
SKYLICENSE_MFA_ENCRYPTION_KEY_FILE=<绝对路径，必需>
SKYLICENSE_OPERATION_LOG_MAX_ROWS_FILE=<绝对路径，可选>
SKYLICENSE_BACKUP_HMAC_KEY_FILE=<绝对路径，仅离线备份命令>
SKYLICENSE_LICENSE_FILE_SECRET_FILE=<绝对路径，仅客户生成/读取license.dat>
```

同一名称的直接变量和 `_FILE` 不能同时设置。文件必须是绝对路径下、仅所有者可访问的
普通文件，路径各级不能含符号链接或 Windows reparse point；内容必须是严格 UTF-8，
允许工具写入的一个末尾换行并会在读取时移除，值内部不能含换行或 NUL。生产服务优先
使用 `_FILE`；直接变量只适合短期本机验证。备份程序会排除所有已配置的凭据文件，
即使误把它们放进 `resources/`，但仍应把凭据放在部署目录和备份目录之外。

`SKYLICENSE_OPERATION_LOG_HMAC_KEY` 是必需的安装级审计密钥，必须是非零的
64 位十六进制字符串。它独立于许可证文件密钥和 TLS 私钥；服务端会在数据库、
Netty 或 Spring 线程启动前校验它。请把该密钥与数据库备份分开保管但纳入同一套
灾备清单。更换或丢失密钥不会泄露原文，但会使新日志无法与旧的 `ref:v1:` 引用
关联，因此除非有明确的密钥轮换计划，不要在重启时随机生成新值。

`SKYLICENSE_MFA_ENCRYPTION_KEY` 是独立的非零 64 位十六进制值，用于
AES-256-GCM 加密数据库中的 TOTP 种子。它不会进入备份归档，必须与数据库备份分开
保管并在恢复时提供原值；丢失或错误轮换会使已经 enrollment 的账号无法完成 TOTP 登录。

操作日志默认只保留最新 500,000 条，启动时和运行中均会事务性裁剪超过上限的旧行。
需要更长窗口时在启动前设置 `SKYLICENSE_OPERATION_LOG_MAX_ROWS`，但仍应建立数据库
归档周期；提高上限不能替代离线审计归档和磁盘容量监控。

后台与认证端共用同一证书并强制 TLS 1.3。`authTlsServerName` 必须填写客户端
实际传给 SDK 的裸 DNS 名称或数字 IP，不得包含协议、端口、路径、通配符或尾点。
预检使用 JDK 标准 HTTPS 端点识别对该名称执行 SAN 校验；证书仅包含一个无关 SAN
不会通过。前端由服务端同源提供时保持 `allowedWebOrigins` 为空；分离部署时只能填写精确的 HTTP(S) Origin，不允许通配符、路径或凭据。

服务端为内置管理前端统一下发 Content Security Policy：脚本和 API 连接仅允许同源，禁止内联脚本、`eval`、框架嵌入和插件对象。当前 Vue/Element Plus 模板仍使用动态样式，因此样式暂时保留 `'unsafe-inline'`。分离部署的前端页面不会继承 API 服务端的响应头，必须在其 CDN 或 Web 服务器上单独配置等价 CSP；CORS 不能替代 CSP。

`config.json` 使用严格 UTF-8 JSON 解析：九个必需字段必须各出现一次，未知字段、重复字段、缺失字段、尾随内容、符号链接和超过 1 MiB 的文件都会被拒绝。Build ID 白名单最多 1024 项，外部 Web Origin 最多 256 项；热加载解析或校验失败时继续使用旧快照，首次启动则直接失败。端口、TLS 路径、`authTlsServerName` 和 Web Origin 都属于重启边界。

管理会话使用 `__Host-skylicense_session` HttpOnly Cookie，Cookie 只包含每次登录新生成的 256 位 opaque 随机值，不返回给 JavaScript，也不写入 Web Storage。SQLite 只保存 Cookie 的 SHA-256 摘要、用户 ID、独立的 CSRF 值、创建时间和过期时间。所有 POST、PUT、PATCH、DELETE 请求必须携带由登录或 `/api/auth/session` 返回的 `X-CSRF-Token`，服务端还会核对 `Origin`。同源部署使用 `SameSite=Strict`；只要配置了 `allowedWebOrigins`，Cookie 就使用 `SameSite=None` 以支持分离前端，因此生产 Origin 必须为 HTTPS。部分浏览器会阻止跨站第三方 Cookie，管理前端与 API 应优先同源部署，至少也应使用同一站点下的不同子域。Schema v4 迁移会主动清除旧 v3 JWT 会话，升级后管理员必须重新登录。

会话授权由 SQLite `web_session` 白名单持久化。数据库只保存 Cookie 的 SHA-256 摘要、用户 ID、独立 CSRF 值、创建时间和过期时间，不保存原始 Cookie；登出删除记录，决定在服务端重启后仍然有效。每个用户最多保留 20 个并发会话，全局最多 100,000 个，创建新会话时清理过期记录。备份 `web_magiclicense.db` 时必须包含这些会话和撤销状态。

## 4. 构建与启动

修改管理前端后，先使用 Node.js `^20.19.0` 或 `>=22.12.0` 按锁文件构建，并将 `dist` 完整镜像到服务端 `src/main/resources/static`；不能只覆盖新文件而保留旧哈希资源：

```powershell
cd F:\Code\Source\skylicense
npm ci
npm run build
```

服务端要求 Java 17 或更高版本：

```powershell
.\gradlew.bat clean test :Client-Side:test bootJar --no-daemon --warning-mode all
java -jar .\build\libs\SkyLicense-Server.jar
```

客户 SDK 应从 `package-sdk-release` 产生且通过 provenance/SHA-256 校验的正式 Release
获取，不应使用仓库当前的 CI 测试原生文件临时打包。

正式服务端产物只使用标准 `bootJar` 输出。旧的本机 JNIC 任务已删除：它曾从个人
下载目录执行未校验的外部 JAR，配置还引用了已经移除的旧组件。服务端混淆不是安全
边界。以后如确需商业混淆器，必须放在隔离的发布任务中，对工具本体固定并校验
SHA-256，保留 Spring/Jackson/ORMLite 所需反射元数据，并对变换后的最终 JAR 重新执行
完整测试、部署预检和签名；不得在开发机上直接替换正式产物。

部署目录至少包含：

```text
SkyLicense-Server.jar
config.json
certs/auth-chain.pem
certs/auth-key.pem
resources/
```

只有全新部署可以没有 `web_magiclicense.db`：服务会在第一次正式启动时创建数据库并
收紧其权限。升级或恢复必须包含已有数据库，以及当时存在的
`web_magiclicense.db-wal`/`web_magiclicense.db-shm` sidecar。只读预检不会创建
数据库；它只检查已有数据库，并确认服务账号能够在父目录中创建数据库。

必须从该目录启动，因为配置、数据库和资源目录均相对当前工作目录。开放 Web HTTPS 端口和原生认证端口。首次创建 `admin` 后删除 bootstrap 密码环境变量并立即修改管理员密码。

正式启动或升级前，必须使用与服务进程相同的工作目录、运行账号和环境变量执行只读预检：

```powershell
java -jar .\SkyLicense-Server.jar --validate-config
```

Linux 命令相同。成功时首行固定输出 `deployment_validation=ok`，并输出证书指纹、
外部 TLS 主机名和到期时间、数据库 schema、有效管理员存在状态及受保护资源数量。
预检会执行严格配置和审计变量检查、本机 TLS 1.3 私钥持有证明、证书链顺序/
有效期/SAN/用途及实际主机名匹配、SQLite `quick_check` 和高版本 schema 拒绝、
数据库目录引用的全部资源 JAR 解析及目录权限检查；不会创建缺失的数据库或资源目录。正式启动
会在打开数据库和监听端口前自动重复同一套预检，不能通过跳过命令绕过门禁。
POSIX 部署中的私钥、数据库及 sidecar、资源目录必须为 owner-only 权限；NTFS
上这些路径必须由专用服务账号所有，且 ACL 不能包含任何其他主体的允许条目。
部署工作目录本身也必须为 owner-only。正式进程会在打开数据库前取得并持续持有
`.skylicense.lock` 的操作系统排他锁；同一工作目录的第二个服务进程会立即失败，
避免两个进程同时修改 SQLite 和资源目录。`--validate-config` 保持只读，不创建或
获取该锁。

首次部署没有有效管理员时，预检要求一次性 bootstrap 密码。已有有效管理员后仍设置 `SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD` 会被预检和正式启动拒绝，防止一次性凭据长期留在服务环境。管理员初始化在任何监听端口开放前完成。`config.json` 缺失时服务端直接失败，不会自动写出一个无法用于生产的默认模板。

未启用 MFA 的管理员只允许访问本人会话/MFA 状态、修改密码、完成 enrollment 和登出；
其他 `/api/*` 请求由会话过滤器返回 403 并写入安全审计。因此首次登录应先修改
bootstrap 密码并重新登录，再从“账户安全”启用 TOTP：验证当前密码，扫描 QR 或录入
手动密钥，提交 6 位代码，然后把只显示一次的恢复码保存到密码管理器。管理员不能自行
禁用 MFA；普通用户启用、禁用或任何用户重建恢复码都会撤销该用户的全部会话和未完成挑战。已启用 MFA 的账号后续登录在密码
校验后只得到 5 分钟、最多 5 次尝试的摘要挑战；完成 TOTP 或一次性恢复码验证后才创建
Web 会话。账号、来源地址、MFA 挑战和 MFA 管理操作的失败计数保存在 SQLite，服务重启
不会清空锁定；管理操作按账号独立限制为 5 次/5 分钟。

服务端会在启动 Web Spring 应用前等待原生认证端口完成 TLS 初始化和绑定；证书/私钥不匹配、证书过期或用途错误、端口被占用或 10 秒内未就绪都会使整个进程启动失败，不会留下只有管理后台而没有认证服务的半可用状态。

启动前先确认 `config.json` 中的 `allowedClientBuildIds` 已填入发布 SDK 输出的
64 位 Build ID，并在同一个进程环境中设置审计密钥。Windows PowerShell 示例：

```powershell
$env:SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE = 'C:\ProgramData\SkyLicense\secrets\operation-log-hmac.txt'
$env:SKYLICENSE_MFA_ENCRYPTION_KEY_FILE = 'C:\ProgramData\SkyLicense\secrets\mfa-encryption-key.txt'
$env:SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE = 'C:\ProgramData\SkyLicense\secrets\bootstrap-admin.txt'
java -jar .\build\libs\SkyLicense-Server.jar
```

Linux 示例：

```bash
export SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE='/run/credentials/skylicense.service/operation-log-hmac'
export SKYLICENSE_MFA_ENCRYPTION_KEY_FILE='/run/credentials/skylicense.service/mfa-encryption-key'
export SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE='/run/credentials/skylicense.service/bootstrap-admin-password'
exec java -jar ./build/libs/SkyLicense-Server.jar
```

正式环境不要把上述值写入 shell 历史、命令行参数或仓库；应使用 Windows 服务
专用 ACL 凭据文件或 systemd `LoadCredential=`。管理员创建成功后移除 bootstrap
直接变量/`_FILE` 映射和凭据文件，但保留并安全备份审计 HMAC 密钥。

原生认证监听器启动前会读取数据库中的 `program_version` 资源目录，并只加载其中引用的
JAR。目录为空允许首次通过后台上传版本；数据库引用的文件缺失、JAR 无效或其
`Name`/`Version` 与目录记录不一致会拒绝整个服务启动。未被数据库引用的 `.jar` 和
`.jar.part` 会先移入 `resources.quarantine/`，既不会加载也不会进入备份。运行时重载
失败则保持上一份有效快照。

Linux 建议使用专用低权限用户和 systemd `EnvironmentFile`，并将工作目录、数据库、资源目录权限限制给该用户。不要以 root 运行服务端。

Windows 同样必须使用专用低权限服务账号。部署工具应先把 `auth-key.pem`、既有
`web_magiclicense.db`/`-wal`/`-shm` 和 `resources` 的所有者改为该账号，再禁用
ACL 继承并删除其他主体的允许规则；私钥只授予读取，数据库和资源授予修改。
不要依赖管理员组、`Users`、`Everyone` 或共享目录权限。首次创建数据库以及运行中
出现的 SQLite sidecar 会由服务端立即收紧为 owner-only；已有宽松文件会在预检时
被拒绝，需由部署账号修复后再启动。

SQLite 启动时使用 WAL、`synchronous=FULL`、10 秒 busy timeout、外键检查和 1000 页自动 checkpoint。服务端会在建表或迁移前执行 `PRAGMA quick_check`，再在事务中按 `PRAGMA user_version` 执行前向迁移；高于当前程序支持版本的数据库会拒绝打开，避免旧服务端破坏新 schema。schema 迁移不代替部署备份。

当前 schema 为 v9。迁移会安装 SQLite 关系触发器，保护程序归属用户、程序版本归属程序、许可证的程序/所有者一致性、验证日志上下文、封禁记录、MFA 挑战和 Web 会话用户引用，并阻止直接删除仍有依赖记录的用户或程序。启动和 `/health/ready` 会再次扫描孤儿关系；发现缺少触发器、触发器被篡改或已有孤儿行时服务 fail-closed，返回 503 或拒绝启动。未知授权码失败日志允许使用 `(license_id, program_id, user_id)=(0,0,0)` 哨兵；许可证删除后历史 `auth_log` 可保留，但新写入的非零许可证引用必须存在且上下文匹配。不要绕过服务直接修改父子表；需要迁移或修复时先从已验证备份恢复并运行预检。

Schema v5 会去除既有用户名首尾空格并建立 ASCII 大小写不敏感唯一索引。Schema v6
在 `ban_record(status, expiration_date)` 上增加到期扫描索引，并由服务启动和每分钟
定时任务把到期规则原子标记为失效，再重新计算受影响许可证。若旧库
存在 `Alice`/`alice` 或仅首尾空格不同的冲突账号，迁移会回滚并拒绝启动；部署前
应在备份副本中消解冲突。旧的可打印非安全字符用户名仍可登录，但创建或改名只接受
3-64 位字母、数字、点、下划线和连字符。

服务启动还会执行一次幂等的原生身份规范化：可解析的许可证绑定、IP 封禁和未完成
认证日志统一为规范 IPv4/IPv6，并对许可证 IP/HWID 列表去重。无法解析的旧 IP 和
不符合当前 32 字节 Base64 格式的旧 HWID 会保留并计入迁移报告，不会静默删除；
管理员应根据报告在后台明确解绑。完成标记写入 `system_metadata`。

## 5. 后台业务流程

1. 管理员完成强制 MFA enrollment 后，创建普通用户并设置最大程序数；需要程序归属普通用户时，由该用户创建程序。
2. 创建程序后确定最终名称。程序名称全局大小写不敏感唯一，上传任意版本后禁止重命名。
3. 上传受保护 JAR。文件最大 64 MiB，根目录必须包含一个 `settings.yml`。
4. 创建许可证。管理员代发时许可证自动归属程序所有者。
5. 将许可证生成客户专属 `license.dat`，交付客户启动器。
6. 通过验证日志查看准确拒绝原因，通过许可证详情执行封禁、解封和解绑。

用户更新接口使用独立的部分更新模型；省略角色、密码或最大程序数字段会保留原值。修改身份字段或禁用用户时，旧 Web 会话会与用户更新在同一数据库事务内撤销。
服务端始终要求至少保留一个已启用的 `ADMIN`，因此在轮换管理员前应先创建并验证第二个管理员账号。
每个管理员账号都必须启用 MFA 才能使用管理 API，并且不能自行禁用 MFA。
管理员详情页可由另一名管理员执行“重置 MFA”：请求必须重新验证操作者密码，并在操作者
已启用 MFA 时提供 TOTP 或未使用恢复码；目标不能是操作者本人，且必须已启用 MFA。重置
只清除目标的 TOTP/恢复码并撤销目标会话和挑战，不会撤销操作者会话。若唯一管理员丢失
验证器和所有恢复码，不能通过直接改 SQLite 绕过；应使用预先验证的第二管理员或按组织
的 break-glass 流程恢复并保留审计证据。

## 6. 受保护资源格式

```yaml
Name: MyPlugin
Version: 1.0.0
EntryClass: com.example.protected.Bootstrap
EntryPoint: start
InfPort: false
KeepClasses:
  - "com/example/reflective/[\\s\\S]*"
```

`Name`、Web 程序名和客户端参数必须完全一致；`Version`、上传版本和客户端参数也必须完全一致。两者均为 1–64 位安全 ASCII 标识，只能使用字母、数字、点、下划线、加号和连字符。入口必须存在于上传 JAR 中，并提供无参数公开静态方法，例如 `public static void start()`；不满足时服务端拒绝上传或数据库目录资源校验。

`KeepClasses` 使用 RE2/J 正则匹配 JVM 内部类名（斜杠分隔）。匹配的类仍受会话资源加密保护，但跳过方法调用加密和随机字节码变异，适用于反射、序列化或框架扫描敏感的类。列表为空时全部类执行转换。`InfPort` 仅为旧 JAR 兼容保留，协议 v4 不使用该字段，固定填写 `false`。

## 7. 许可证策略

- `bindableIps=0`：不限制且不记录 IP；大于零时首次成功认证占用一个 IP 名额。
- `bindableHwids=0`：不限制 HWID；大于零时首次成功认证占用一个机器名额。
- 非零绑定上限不能降低到当前已绑定数量以下；后台会拒绝这种更新，应先明确解绑不再使用的 IP/HWID。许可证策略更新和原生资源释放提交共用授权锁，因此在途认证不能绕过刚收紧的上限。
- `expirationDate=null`：永久有效；否则使用服务端本地时区的 `yyyy-MM-dd-HH:mm`。
- `maxDailyAuth=0`：不限制；大于零时按服务端自然日统计资源释放次数，不统计心跳。
- 服务端先创建内部 `PENDING` 预留；准备写出加密资源时，在同一事务中提交 IP/HWID、`lastAuthTime` 和每日额度，将日志改为 `RELEASED`，然后才释放密文。客户端 ACK 只把 `RELEASED` 确认为 `OK`，不能退款已经取得的资源。
- 当达到每日上限时，`OK`、`PENDING`、`RELEASED` 和 `DELIVERY_UNCONFIRMED` 都参与计数。资源释放前失败记为 `DELIVERY_FAILED`，不占绑定或额度；资源释放后断连、30 秒 ACK 超时、ACK 签名错误、入口初始化未确认或确认帧失败记为 `DELIVERY_UNCONFIRMED`，保留绑定和额度并销毁会话。客户端返回 `DELIVERY_ACK_ERROR` 后必须在新进程中处理，不得依赖失败重试规避额度。
- 服务启动时会把遗留的 `PENDING` 恢复为 `DELIVERY_FAILED`，把遗留的 `RELEASED` 恢复为 `DELIVERY_UNCONFIRMED`。只有前者不会留下 IP/HWID 绑定。
- 清除正在使用的绑定时，服务端会在同一事务中取消匹配的 `PENDING`，并把匹配的 `RELEASED` 改为 `DELIVERY_UNCONFIRMED`，防止在途 ACK 把刚解绑的 IP/HWID 写回；已释放额度不会退回。已经提交的会话会在心跳时撤销。封禁许可证、禁用用户或程序后，心跳同样会撤销现有会话。
- 删除程序版本、从资源目录移走版本，或重载时发现同一 `Name/Version` 的 JAR 内容发生变化时，匹配租约也会被标记撤销；客户端下一次心跳收到签名 `REVOKE` 后会清零本地会话密钥。未变化的定时资源重扫不会中断在线客户端。

程序级 IP/HWID/QQ/CODE 规则只作用于所选程序。同一值可以在不同程序建立独立规则。普通用户必须选择自己的程序；只有管理员可以创建跨程序全局规则。
封禁列表中的 `status=1` 表示当前生效，`status=0` 表示已解除或已到期；删除其中一条
重叠规则时，只有在没有其他生效规则覆盖时才恢复许可证。过期规则不会再次参与认证
检查，后台页面应以状态字段而不是仅凭时间字符串判断生效性。

## 8. 客户授权文件与启动

每个客户部署使用独立随机密钥：

```powershell
$secretPath = 'C:\ProgramData\SkyLicenseClient\secrets\license-file-secret.txt'
# 使用密码学随机源生成至少32字节的客户专属值并写入该文件，再将ACL限制为客户运行账号。
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = $secretPath
```

交互式生成 `SKYLIC03` 文件：

```powershell
.\gradlew.bat :Client-Side:classes
java -cp Client-Side\build\classes\java\main cn.sky.license.LicenseFileTool .\license.dat
```

在独立交付目录中也可以直接使用已经通过发布门禁的 SDK JAR：

```powershell
java -cp .\SkyLicense.jar cn.sky.license.LicenseFileTool .\license.dat
```

`license.dat` 必须位于客户程序 classpath 根目录，运行时必须提供相同部署密钥。许可证不能作为命令行参数传递，也不要把许可证或部署密钥提交到源码仓库。

### 8.1 Java 宿主接入

客户宿主只负责实现 SDK 的 `PluginProxy` 适配器；受保护 JAR 的入口类由服务端
在认证成功后下发，不应再把同一份入口类放进客户宿主包。最小独立宿主示例：

```java
import cn.sky.license.PluginProxy;
import cn.sky.license.Resource;
import cn.sky.license.Response;
import cn.sky.license.SkyLicense;

import java.io.File;
import java.io.InputStream;

public final class LicenseBootstrap implements PluginProxy {
    public static void main(String[] args) {
        SkyLicense client = new SkyLicense(new LicenseBootstrap());
        Response response = client.authenticate(
                "license.example.com:13331", "MyPlugin", "1.0.0");
        if (response != Response.ACCEPT) {
            throw new IllegalStateException("License authentication failed: " + response);
        }
        // ACCEPT means resource load, entry return, heartbeat and ACK all succeeded.
    }

    @Override public File getDataFolder() { return new File("data"); }
    @Override public void info(String text) { System.err.println(text); }
    @Override public void disablePlugin() { throw new IllegalStateException("Plugin disabled"); }
    @Override public InputStream getResource(String name) {
        return LicenseBootstrap.class.getClassLoader().getResourceAsStream(name);
    }
    @Override public Resource getResourceType() { return Resource.CLEAR_LOWERCASE; }
    @Override public boolean isPrimaryThread() { return true; }
}
```

`MyPlugin` 和 `1.0.0` 必须分别等于后台程序名和上传版本的 `Name`/`Version`，
且只使用安全 ASCII 标识。地址只写 `主机名[:端口]`，不能写 `https://`、路径或
查询字符串；证书 SAN 必须包含该主机名。SDK 当前发布门禁只包含 Windows/Linux
x86-64，因此 32 位 JVM 或 macOS 不属于可交付目标。

SDK 会把原生库和签名清单提取到 `PluginProxy.getDataFolder()/authlib`，并把目录与
文件权限收紧为仅运行账号可访问。该数据目录必须由运行账号独占，不能放在所有用户
可写的共享目录中，也不能让多个不同系统账号共用。

`license.dat`、宿主 JAR 和 SDK JAR 放在同一个客户目录时，使用 classpath 启动，
不要直接用 `java -jar`（后者不会自动把当前目录加入 classpath）：

```powershell
# Windows；点号让 classloader 找到当前目录的 license.dat
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = 'C:\ProgramData\SkyLicenseClient\secrets\license-file-secret.txt'
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading `
  -cp ".;customer-app.jar;SkyLicense.jar" LicenseBootstrap
```

```bash
# Linux
export SKYLICENSE_LICENSE_FILE_SECRET_FILE='/run/credentials/customer-app.service/license-file-secret'
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading \
  -cp ".:customer-app.jar:SkyLicense.jar" LicenseBootstrap
```

生成 `license.dat` 时使用的 `SKYLICENSE_LICENSE_FILE_SECRET[_FILE]` 必须与客户启动时
解析到完全相同的值；每个客户应使用独立随机值，可用 `openssl rand -base64 48`
生成后直接写入受限凭据文件，避免输出到 shell 历史。
`ACCEPT` 以外的结果应先查看服务端验证日志：网络/忙碌类结果可由宿主按
`Response.retry()` 做有限重试，入口异常、绑定、额度、撤销和
`DELIVERY_ACK_ERROR` 都不能在同一 JVM 进程内重试，需修复原因后重新启动进程。
资源入口必须在服务端 30 秒 ACK 窗口内完成初始化并返回。

一个 JVM 进程只允许一个原生认证流程和一个受保护资源会话。并发调用会返回
`AUTHENTICATION_IN_PROGRESS`，成功后的重复调用返回
`SESSION_ALREADY_INITIALIZED`。如果服务端已经开始释放资源，后续传输、解密、
类定义、入口或 ACK 任一阶段失败都会撤销本地能力；即使错误最初表现为网络中断，
也必须重启 JVM，不能在同一进程重新认证。

SDK 会把 Rust 返回的带详情错误按前缀归并到稳定的 `Response` 常量，例如网络
读写错误、客户端构建错误、HWID、资源、心跳和保护激活错误；内部错误详情不会
原样暴露给宿主。无法识别的新错误统一返回 `Response.UNKNOWN_ERROR`。

Strict 客户端在 JDK 9 及以上使用：

```text
-XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading
```

Java 调用 `SkyLicense.authenticate("license.example.com:13331", "MyPlugin", "1.0.0")`。地址不能包含协议或路径。返回 `ACCEPT` 时资源已加载、心跳已启动、入口方法已成功返回且服务端已确认 ACK，业务代码不得重复调用入口。入口类、方法或执行异常分别返回 `ENTRY_CLASS_NOT_FOUND`、`ENTRY_POINT_NOT_FOUND` 或 `ENTRY_POINT_EXCEPTION`；ACK 写入、超时或确认失败返回终态 `DELIVERY_ACK_ERROR`。这些失败都会销毁本地分发密钥，不能在同一进程内重试；应在服务恢复后重启宿主进程。入口方法应在 30 秒服务端 ACK 窗口内完成初始化并返回。

## 9. 运维与备份

Web 管理端口提供两个无需 Cookie、CSRF 或管理员权限的最小健康探针：

```text
GET /health/live
GET /health/ready
```

`/health/live` 只证明当前 Web 进程仍能处理请求并返回 HTTP 200。
`/health/ready` 仅在服务未进入关闭流程、协议 v4 TLS 监听器仍可接受新连接、SQLite
最小查询成功且操作审计持久化健康时返回 HTTP 200；否则返回 HTTP 503。响应体仅为
`{"status":"UP"}` 或 `{"status":"DOWN"}`，不会暴露端口、路径、证书或数据库原因，
并统一携带 `Cache-Control: no-store`。SQLite 检查最多缓存约 2 秒，防止公开探针高频
占用连接池。负载均衡器应使用 ready 决定是否接收新流量，进程管理器只能在 live
持续失败时重启；监控客户端必须验证公共 CA、TLS 1.3 和主机名，禁止使用跳过证书
验证的探针命令。管理端口仍应限制在管理网或受控负载均衡器来源。

应用日志写入 `logs/latest.log`，消息和异常中的 CR/LF 会编码后单行保存，时间戳使用
UTC。文件在自然日切换或达到 50 MiB 时滚动到 `logs/archive/`；单日最多 20 个索引，
归档动作按 30 天、200 个文件或累计 2 GiB 任一上限清理。清理只在发生滚动时运行，
因此必须独立监控磁盘容量，并把需要长期保留的安全日志发送到独立、访问受控且具有
不可变保留策略的集中日志系统。WinSW 自身的 wrapper 输出滚动策略与应用日志独立。

离线备份使用独立且固定的 256 位认证密钥，不能与审计 HMAC、TLS 私钥或许可证
文件密钥复用：

```text
SKYLICENSE_BACKUP_HMAC_KEY_FILE=<备份服务专用owner-only凭据文件的绝对路径>
```

先通过服务管理器正常停止服务，再把归档写到生产工作目录以外、由服务账号独占且
底层已加密的备份卷：

```text
java -jar SkyLicense-Server.jar --create-backup /secure-backups/skylicense.skybackup
java -jar SkyLicense-Server.jar --verify-backup /secure-backups/skylicense.skybackup
```

创建命令会取得与正常服务相同的 `.skylicense.lock`，因此服务仍在运行时必定失败；
随后执行 WAL `TRUNCATE` checkpoint、SQLite `quick_check`，再归档数据库、配置、
受保护资源和位于工作目录内的 TLS 证书链。每个文件都有 SHA-256，清单再由域分离
HMAC-SHA-256 认证。TLS 私钥、私钥口令、bootstrap 密码、审计 HMAC 和备份 HMAC
均不会进入归档，必须由企业密钥管理器独立恢复。

恢复不会直接覆盖生产目录。先验证并解压到一个尚不存在的新目录：

```text
java -jar SkyLicense-Server.jar --extract-backup \
  /secure-backups/skylicense.skybackup /opt/skylicense-restore
```

再从密钥管理器配置 TLS 私钥和所有环境密钥，以目标服务账号修复 owner-only 权限，
运行 `--validate-config`。只有预检通过后才能用服务管理器切换工作目录。至少每季度在
隔离主机执行一次完整恢复演练；仅验证归档哈希不能证明服务、证书和密钥能够恢复。

- 控制台仅提供 `help`、`online`、`refresh`、`reload`、`stop`。
- 资源重载只允许通过本机控制台命令或带管理员会话、Origin 和 CSRF 校验的 Web API 触发；旧的 `reload.txt` 文件触发器已移除。
- `online` 只输出按程序聚合的活动会话数量，不写入许可证、IP、HWID 或 Session ID。
- `stop` 不再直接调用 `System.exit`。它与 Spring `ContextClosedEvent`、systemd `SIGTERM` 共用同一个有界关闭协调器；正常停机应优先使用该命令或服务管理器的 stop 操作。
- 关闭顺序固定为：关闭新认证注册门并停止监听 → 撤销全部原生租约并清零会话密钥 → 关闭 Netty 客户端/事件循环 → 停止调度器和命令执行器 → Spring graceful shutdown → SQLite WAL checkpoint 并关闭连接池。关闭等待有上限，超时会记录告警但不会重新接受连接。
- `reload` 会先原子重扫资源，再验证并提交配置策略。`debug`、Build ID 白名单和不降低的 security epoch 可热加载；端口、证书路径、CORS 变化或 epoch 回退会被拒绝并要求重启。策略收紧会立即标记不再合规的活动客户端租约，后续心跳会返回签名撤销并清零会话密钥；握手中和后续心跳也会重新检查当前策略。
- 管理员概览中的“活动后台会话”来自持久化 `web_session` 白名单；达到全局容量时新登录会 fail-closed，已有会话不会被全局淘汰。
- 管理员概览同时显示当前有效的原生客户端租约；客户端会话在 90 秒无有效心跳后由后台清理。
- 心跳间隔约 30 秒，本地和服务端租约为 90 秒。连续无法获得认证 PONG 时客户端停止受保护分发。
- 停止服务后备份 `web_magiclicense.db`、数据库目录引用的 `resources/` 文件、
  `config.json` 和证书。不要只备份数据库而遗漏上传资源；孤立文件位于
  `resources.quarantine/`，不属于可加载制品，不会被归档。
- 操作审计的密码、Cookie、Token 会替换为 `***`；许可证、IP、HWID、QQ、封禁值和审计来源地址只保留稳定的不可逆 `ref:v1:` 引用。来源引用使用实际 TCP 对端计算，不信任未经配置的 `X-Forwarded-For`/`X-Real-IP`。
- 审计引用由 `SKYLICENSE_OPERATION_LOG_HMAC_KEY` 通过域分离 HMAC 生成；成功和
  拒绝的带注解写操作都会记录 `outcome=SUCCESS` 或 `outcome=REJECTED`。业务执行前
  先写入 `outcome=ATTEMPT` 预审计；预审计数据库写入失败时接口返回 HTTP 503，业务
  方法不会执行。业务完成阶段写入失败会保留 `ATTEMPT`、将审计服务标记为不健康，
  `/health/ready` 返回 HTTP 503，直到审计写入恢复。旧 `ref:<sha256>` 日志仍可读取，
  但不会与新引用互相匹配。
- 脱敏后的操作详情超过 2,000 UTF-8 字节时不会保存非法的字符串片段，而是保存合法
  JSON：`truncated=true`、原始字节数 `originalLength` 和键控
  `detailDigest=ref:v1:...`。摘要可用于同一安装内关联重复事件，不能还原详情。
- 登录成功/失败、登出、修改密码和管理员资源重载均有审计事件。登录尚未建立
  会话时使用 `userId=0`/`username=anonymous`；过滤器只记录高信号的登录 Origin、
  CSRF、Origin 和重复认证状态拒绝，不记录普通未提供会话的 401。拒绝审计按
  HMAC 化的来源和事件维度做有界的一分钟抑制，防止持续失败请求填满 SQLite；被
  有意抑制的匿名登录审计不会阻止登录业务，只有实际数据库故障才会返回 503。
- 旧 `magiclicense.db` 只用于一次性迁移；系统会先创建 `.pre-web-migration-v1.bak`。迁移未映射记录时，先创建同名 Web 程序再重启重试。

Linux 使用 systemd 时，`ExecStop` 可省略，让 systemd 发送 `SIGTERM`：

仓库中的 `deployment/linux/` 提供完整的主服务、首次 bootstrap drop-in、离线备份
service/timer 和安装说明；`deployment/windows/` 提供 WinSW 配置、SHA-256 校验安装器、
严格 NTFS ACL 设置和离线备份脚本。下面片段仅展示主服务的关键凭据映射：

```ini
[Service]
User=skylicense
WorkingDirectory=/opt/skylicense
LoadCredential=operation-log-hmac:/etc/skylicense/credentials/operation-log-hmac
Environment=SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE=%d/operation-log-hmac
ExecStart=/usr/bin/java -jar /opt/skylicense/SkyLicense-Server.jar
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=on-failure
```

首次启动临时增加 `LoadCredential=bootstrap-admin-password:...` 和
`Environment=SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE=%d/bootstrap-admin-password`；创建
管理员后立即删除这两行及源凭据。加密 PEM 同理可映射 `tls-key-password`。
`LoadCredential` 源文件和 `auth-key.pem` 必须限制为相应管理账号/服务账号可读；
升级或备份前先执行
`systemctl stop skylicense`，确认日志出现 `SkyLicense services stopped` 后再复制
`web_magiclicense.db`、数据库目录引用的资源文件、`config.json` 和证书；不要复制
`resources.quarantine/`。不要使用 `kill -9` 作为正常发布步骤。

证书轮换分三步：先发布“当前证书主 Pin + 下一张证书次 Pin”的原生客户端；确认目标客户完成升级后切换服务端证书；最后发布仅保留新证书主 Pin 的清理版本。`SKYLICENSE_CERT_SHA256_NEXT` 不能单独设置，也不能与主 Pin 相同。WebPKI 证书链和主机名校验始终执行，双 Pin 不会放宽 CA 信任。
