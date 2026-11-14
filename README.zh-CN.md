[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense

包含许可证服务端、管理网站和 Java SDK，通过 TLS 1.3 在线验证并下发受保护 Java 程序。

先按下方完整流程跑通：服务端 → Web 管理后台 → 上传受保护 JAR → 签发授权文件 → 客户端验证。
首次使用推荐 Java 基础版；需要额外运行时防护时再按原生版发布流程接入。

| 组件 | 使用文档 |
| --- | --- |
| 服务端配置、账号及运维 | [服务端 README](src/README.zh-CN.md) |
| Web 操作、前端构建及 HTTPS 开发 | [Web README](web/README.zh-CN.md) |
| Java 基础版/原生版 SDK 与客户接入 | [Java SDK README](Client-Side/README.zh-CN.md) |
| Rust 原生构建、签名与平台检查 | [原生 README](native/README.zh-CN.md) |
| 受保护程序 JAR | [示例 README](examples/basic-app/README.zh-CN.md) |
| 本地运行包与生产服务部署 | [部署索引](deployment/README.zh-CN.md) |

已验证范围及限制见 [验证报告](VALIDATION.md)；CI 测试构建不能作为正式原生发行包交付。

## 从这里开始：基础可用版

基础版不依赖 DLL/SO，已实现许可证检查、加密类下发、入口执行、加载 ACK、签名心跳和在线撤销。
基础版有意不包含原生反调试、反转储、内存保护，这些能力属于独立的原生 SDK；基础版持久化安装标识**不是硬件指纹**。

### 1. 构建运行包

安装完整 **JDK 17 或 21**，确认 `java`、`javac`、`keytool` 可用。本机体验使用普通用户终端，不要以管理员/root 身份运行：

```sh
git clone https://github.com/SharkL0ve/SkyLicense.git
cd SkyLicense
```

Windows PowerShell：

```powershell
.\gradlew.bat :test :Client-Side:test basicReleaseZip --no-daemon --warning-mode all
```

Linux：

```sh
./gradlew :test :Client-Side:test basicReleaseZip --no-daemon --warning-mode all
```

生成 `build/distributions/SkyLicense-Basic-1.0.0.zip`，解压到独立可写目录，不要把业务数据库放在 build 下。
包内包含服务端、内置网站、基础 SDK、受保护示例和初始化/启动脚本。Git 不包含真实运行配置或凭据。

### 2. 初始化并启动

在解压后的 SkyLicense-Basic 目录打开 PowerShell：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\SetupLocal.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\StartServer.ps1
```

按提示设置初始管理员密码：12–128 位，大小写、数字、符号至少三类。初始化生成私有 runtime/customer、
独立随机密钥、localhost 证书和基础 SDK 白名单；只执行一次，已有目录不会覆盖。

保持服务端窗口运行。浏览器打开 **https://localhost:18443/**，认证地址为 **localhost:13331**。
自签名证书仅包含 localhost/127.0.0.1，30 天到期；本机测试可确认自己站点的浏览器证书例外，或导入个人可信存储。
Java 客户端明确加载这张证书，并继续校验主机名。

### 3. 初始化管理员

1. 用户名 admin，密码为初始化时设置的值。
2. 左下角账户菜单修改密码，重新登录。
3. 账户安全中输入当前密码，扫描验证器二维码，提交六位验证码。
4. 安全保存只显示一次的恢复码，再使用 TOTP 或未使用恢复码登录。
5. 管理员创建后删除 `runtime/secrets/bootstrap-admin.txt`；后续启动不再映射该凭据。

管理员未完成 MFA 时业务 API 返回 403，属于预期限制。建议创建并验证第二个 MFA 管理员作为恢复通道。
当前界面使用中文，英文文档也标出了关键菜单。

### 4. 发布示例、签发许可证

1. 内容管理 → 程序管理，创建 **DemoApp**。
2. 上传包内 **DemoApp-1.0.0.jar**，版本 **1.0.0**。
3. 为该程序创建许可证，初次建议一个 IP、一个安装标识、每日验证不限。
4. 另开终端，在解压目录执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\MakeLicense.ps1
```

按提示输入许可证，生成 `customer/license.dat`（SKYLIC03 格式）。授权码不作为命令行参数。
交互终端支持隐藏输入；重定向或 IDE 控制台不一定隐藏回显。

### 5. 启动客户程序并验证撤销

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\StartClient.ps1
```

成功输出：

```text
Protected DemoApp started successfully.
License accepted; protected entry completed; heartbeat active.
```

后台验证日志最终为 OK。客户端保持运行，每约 20 秒心跳；后台封禁后，后续心跳收到签名撤销并退出。
在服务端窗口输入 stop 正常关闭。以后直接 StartServer/StartClient，不要重复初始化。

Linux 在解压目录运行：

```sh
sh run.sh setup
sh run.sh server
# 完成后台配置后，另一个终端：
sh run.sh license
sh run.sh client
```

基础版和严格模式原生版均已完成 Windows/Linux 真实系统测试，Windows 包内 PowerShell 脚本也已实测。
每台部署主机仍需验收服务账号、文件权限、证书、端口和防火墙配置。

### 6. 把客户端交付到其他电脑

不要把初始化后的服务端 runtime 目录交给客户。客户只接收启动器/SDK、license.dat、该客户独立的授权文件密钥，
以及需要时的公开 CA 证书。远程服务必须使用包含实际域名的证书，同步 authTlsServerName，并开放认证端口。
客户端地址写 license.example.com:13331，不带 https://，也不是 Web 管理端口。
交付前核对 [客户端交付清单](Client-Side/README.zh-CN.md#客户交付清单)。

## 接入自己的应用

受保护 JAR 根目录包含 settings.yml：

```yaml
Name: MyApp
Version: 1.0.0
EntryClass: example.Entry
EntryPoint: start
InfPort: false
KeepClasses: []
```

入口是公开静态无参数方法，例如 `public static void start()`，初始化后及时返回以完成 ACK。
后台程序名、上传版本和客户端参数与 Name/Version 完全一致（包括大小写）。名称/版本为 1–64 位安全 ASCII，
首位字母/数字，后续允许字母、数字、点、下划线、加号和连字符。JAR 最大 64 MiB，上传首个版本后不能改程序名。

通过后台上传以建立文件和版本目录；手工复制到 resources 不会发布，孤立文件会被隔离。
普通配置/图片等非 class 资源及依赖 JAR 放在客户宿主 classpath 或数据目录。
KeepClasses 是匹配斜杠 JVM 类名的 RE2/J 正则；匹配类仍加密传输，但跳过方法改写，适合反射框架。

启动其他程序：

```powershell
.\StartClient.ps1 -Program MyApp -Version 1.0.0
```

已有 Java 宿主实现 `cn.sky.license.PluginProxy` 的六个方法后调用；完整导入、接口契约和生命周期见 [SDK README](Client-Side/README.zh-CN.md)：

```java
BasicLicenseClient client = new BasicLicenseClient(proxy);
Response result = client.authenticate("license.example.com:13331", "MyApp", "1.0.0");
if (result != Response.ACCEPT) {
    throw new IllegalStateException("Authentication failed: " + client.getLastError());
}
// SDK 已执行入口；保留 client，保持宿主运行，关闭时调用 client.close()。
```

disablePlugin 必须真正停用业务；BasicLauncher 在租约撤销时退出进程。一个 JVM 仅允许一个基础版活跃会话。
修复认证/下发失败原因后重启宿主，不要重复执行入口。

## 许可证策略和客户密钥

| 配置 | 语义 |
| --- | --- |
| IP / 安装标识数 | 0 不限；正数限制不同绑定数量，不是同时在线数 |
| 到期时间 | 留空永久；API 格式 yyyy-MM-dd-HH:mm |
| 每日上限 | 0 不限；按服务端自然日统计资源释放，不统计心跳 |
| license.dat | 位于宿主 classpath 根目录 |
| SKYLICENSE_LICENSE_FILE_SECRET_FILE | 客户专属密钥；生成与读取授权文件必须相同 |
| basic-installation.id | 数据目录中的随机持久化身份；保留它才能保留绑定 |

每个客户使用独立密钥。复制安装目录可能复制身份，基础版不提供硬件防克隆、原生签名证明或反调试。
Build ID 仅是软件版本标记，当前为
`7f10d350d700568181fc244d4f3b779c75ab57316ae8e0e573a1802b815c33f0`，epoch 1。
绑定和额度在资源释放时提交，入口/ACK 失败仍可能计费；DELIVERY_UNCONFIRMED 和解绑都不退还已释放资源的额度。
封禁许可证、禁用用户或程序会通过心跳撤销现有租约。

## 远程部署及运行配置

仓库不包含真实配置、数据库、证书、私钥、许可证或客户密钥。SetupLocal 在运行目录生成这些文件。
手工部署参考 [`deployment/config.example.json`](deployment/config.example.json) 和 [DEPLOYMENT.md](DEPLOYMENT.md)。
远程部署使用实际域名证书/私钥，同步 authTlsServerName，并让客户端连接同一域名。
部署目录、资源、数据库、私钥和凭据仅所属服务账号可访问；同源内置前端保持 allowedWebOrigins 为空。

服务端使用 SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE 和 SKYLICENSE_MFA_ENCRYPTION_KEY_FILE 获取独立、固定的审计/MFA 密钥，
各为非零 32 字节十六进制值。bootstrap 仅首次启动，原审计/MFA 密钥须纳入独立灾备，不能每次重启重新生成。

公共 CA 使用 JVM 信任库；私有 CA 用 SKYLICENSE_BASIC_CA_CERT_FILE 指向 PEM。
可选 SKYLICENSE_BASIC_CERT_SHA256 为叶证书 DER 的 SHA-256。包内 StartClient 默认本机证书，远程公共 CA 可直接运行。
以下命令须在同时含 license.dat 和 SkyLicense-basic.jar 的客户目录中执行：

```powershell
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = 'C:\MyCustomer\secrets\license-file-secret.txt'
Remove-Item Env:\SKYLICENSE_BASIC_CA_CERT_FILE -ErrorAction SilentlyContinue
java -cp '.;SkyLicense-basic.jar' cn.sky.license.BasicLauncher license.example.com:13331 MyApp 1.0.0
```

使用相同服务账号、环境和部署目录执行 `java -jar SkyLicense-Server.jar --validate-config`，通过后再启动。
缺配置、TLS 错误或权限不安全时拒绝启动。数据库名 web_magiclicense.db 保留兼容，不要重命名已有业务库。

## 运维、备份和故障定位

- /health/live 和 /health/ready 返回最小 UP/DOWN JSON，就绪失败为 503；探针保留 CA 和主机名验证。
- 验证日志看拒绝原因，操作日志页校验审计链；应用日志在 runtime/logs，时间为 UTC。
- 401 重新登录；403 检查 MFA、角色、Origin/CSRF；程序不匹配检查名称/版本/所有者，NOT_ADDRESS 检查绑定；
  连接错误检查 CA、域名、Pin、端口、防火墙和时钟。
- 停服务后设置原审计/MFA 密钥及独立 SKYLICENSE_BACKUP_HMAC_KEY_FILE，在部署目录执行：

```text
java -jar ../SkyLicense-Server.jar --create-backup <私有备份目录>/backup.skybackup
java -jar ../SkyLicense-Server.jar --verify-backup <备份路径>/backup.skybackup
java -jar ../SkyLicense-Server.jar --extract-backup <备份路径>/backup.skybackup <全新恢复目录>
```

替换尖括号路径；备份位于部署目录之外，恢复目标必须不存在。归档不含 TLS 私钥和环境密钥，须另行保存、恢复权限及凭据，
预检通过后再启动。升级保留 runtime/customer、业务库和密钥，只更新程序及脚本。

## 源码结构、前端开发和测试

src/main/java 是服务端；Client-Side 是 Java SDK；web 是 Vue 前端；native 是新版 SkyLicense-Client 的 Rust 客户端；examples/basic-app 是示例；deployment 是部署工具；tools 是隔离测试。
根目录 Cargo.toml/Cargo.lock 管理 Rust 工作区，与 Gradle 服务端项目共存，三个项目不再需要独立源码目录。
src/main/resources/static 保留内置前端资源，普通服务端构建不强制安装 Node.js。
修改前端需 Node.js ^20.19.0 或 >=22.12.0、npm 10+：

```sh
cd web
npm ci --ignore-scripts
npm run build
```

将 web/dist 完整镜像到 src/main/resources/static，移除旧哈希资源后重新打包；不提交 node_modules 或运行时环境文件。
[Web README](web/README.zh-CN.md) 提供 Windows/Linux 安全复制命令和完整 HTTPS 开发配置；默认 HTTP Vite 服务不能直接当作已配置好的后台登录环境。
API 默认同源 /api。基础版通过 256 项服务端、25 项 SDK 测试及真实认证、入口、ACK、心跳、拒绝、撤销、备份恢复和重启验证。

已通过兼容依赖更新清除前端已知高危告警，仍有 5 项开发工具相关中危告警。对公网部署前请运行 npm audit；功能测试通过不代表已完成全面安全认证。
隔离测试脚本需 Python 3.10+ 与 cryptography：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install cryptography
.\.venv\Scripts\python.exe tools/local-smoke-test.py --basic
.\.venv\Scripts\python.exe tools/test-basic-package.py
```

Linux（包内 PowerShell 脚本测试仅限 Windows）：

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install cryptography
python tools/local-smoke-test.py --basic
```

包内脚本测试验收 Windows 入口；随机凭据及临时目录在源码之外创建。构建和单元测试不依赖运行配置。
构建 bootJar 后，可先运行 python tools/local-smoke-test.py --preflight-only，快速检查私有部署目录、TLS 和配置。
原生增强 SDK 为独立可选流程，:Client-Side:jar 继续拒绝缺失、未签名或加固不合格的原生资产，仓库不分发 CI DLL/SO。
当前 [native 源码](native/README.zh-CN.md) 已替换为新版 SkyLicense-Client，支持当前 TLS/v4 协议。
历史客户端备份不属于当前 Rust 工作区。
安装 Rust 1.97.1、JDK 17/21 与 Python cryptography，先构建 Java 类及服务端，再在根目录运行严格模式真实联调；Windows 还需要 MSVC Build Tools：

```sh
python tools/local-smoke-test.py --native --build-native
```

使用上方虚拟环境中的 Python；Windows 未激活时改用 .\.venv\Scripts\python.exe。

该命令构建并签署 CI 测试原生库、验证平台加固并运行真实受保护 Java 程序，检查认证、入口、ACK、签名心跳、重复认证拒绝、
封禁/到期/额度拒绝、不受信任 TLS、缺失/篡改清单、在线撤销和宿主停用通知，以及审计与备份恢复。
随机凭据和证书仅写入新的私有临时目录，结束后正常关闭测试服务端；公开 CI 身份及测试证书禁止用于生产交付。
正式接入见 [原生客户端指南](native/README.zh-CN.md) 和 [部署手册](DEPLOYMENT.md)。独立程序使用 cn.sky.license.NativeLauncher 并携带两个 JVM 加固参数；
协议对齐、回归覆盖和已知限制见 [验证报告](VALIDATION.md)。
嵌入宿主必须落实 disablePlugin()，退出时调用 SkyLicense.close()。正式发布仍需自己的 TLS、签名身份和 Windows Authenticode 材料。
原生发布和 SDK 打包工作流现均在本仓库，安全门禁继续保留；基础版 Gradle 构建仍不依赖 Rust 或 Node.js。
更多参考 [部署手册](DEPLOYMENT.md)、[API 文档](API-DOC.md)、[Linux](deployment/linux/README.md) / [Windows](deployment/windows/README.md) 服务模板。

许可证见 [LICENSE](LICENSE)。
