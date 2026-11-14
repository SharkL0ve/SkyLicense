[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense 基础可用版 1.0.0

这个包包含服务端、内置管理网站、Java 17 客户端 SDK、受保护示例程序和初始化/启动脚本。
基础 SDK 文件名已统一为 `SkyLicense-basic.jar`；请使用同一包内更新后的脚本。
核心验证使用 TLS 1.3 + v4 协议，保留许可证、到期、IP/部署绑定、额度、资源加密、加载 ACK、心跳与在线撤销。
不依赖 DLL/SO。原生反调试、反转储、内存防护和原生签名发布暂不包含。

## Windows：第一次使用

安装完整 JDK 17 或 21，确保 `java` 和 `javac` 可用。解压整个包到自己的普通可写目录，
打开 PowerShell，进入解压后的 `SkyLicense-Basic` 目录。以下命令均从这个目录执行。
使用普通、非提权终端，文件须归实际运行用户所有，不能归 Administrators 组。
此工具只初始化本机体验环境，不是正式证书或生产服务安装器。

1. 执行 `powershell -NoProfile -ExecutionPolicy Bypass -File .\SetupLocal.ps1`。
   在终端输入并确认初始管理员密码：12–128 位，大小写、数字、符号至少三类。
   脚本生成私有 `runtime/`、`customer/`、随机独立密钥、localhost 测试证书和正确的 Build ID 白名单。
   初始化只执行一次，已有目录时会拒绝覆盖；以后直接运行启动脚本。
2. 执行 `powershell -NoProfile -ExecutionPolicy Bypass -File .\StartServer.ps1`，保持该窗口运行。
   浏览器打开 **https://localhost:18443/**。本机证书为自签名证书，浏览器会提示不受公共 CA 信任；
   可在自己的本机测试站点确认进入，或将本次 `runtime/certs/auth-chain.pem` 导入个人可信证书存储。
   客户端脚本会明确加载这张证书并校验 localhost 主机名，不会跳过 TLS 验证。
3. 用户名 `admin`，密码为步骤 1 设置的值。先从左下角菜单修改密码、重新登录，再在“账户安全”
   绑定验证器并保存恢复码。MFA 完成后重新登录即可访问管理功能。
   首次管理员创建后删除 `runtime/secrets/bootstrap-admin.txt`；启动脚本以后不再映射该凭据。
4. 从“内容管理 → 程序管理”创建 **DemoApp**，进入程序详情，上传本包的 **DemoApp-1.0.0.jar**，
   版本填写 **1.0.0**。在该程序下创建许可证；初次建议 1 个 IP、1 个机器码、每日验证不限。
   “机器码”在基础版中代表本地安装标识，具体限制见下文。
5. 另开 PowerShell，在包目录执行 `powershell -NoProfile -ExecutionPolicy Bypass -File .\MakeLicense.ps1`，
   提示后输入刚创建的许可证。输出 `customer/license.dat`；许可证不作为命令行参数。
6. 执行 `powershell -NoProfile -ExecutionPolicy Bypass -File .\StartClient.ps1`。
   看到 `Protected DemoApp started successfully.` 和
   `License accepted; protected entry completed; heartbeat active.` 就表示认证、资源解密、入口和服务端 ACK 均完成。
   后台验证日志的最终状态为 `OK`。客户端保持运行并每约 20 秒心跳；封禁该许可证后，客户端会收到撤销并退出。

正常停止服务在服务端窗口输入 `stop`。下次直接运行 StartServer、StartClient，不要重复初始化或删除 runtime。
从旧名版本升级时保留已有 runtime/customer 和密钥，只更新程序及脚本；数据库继续使用兼容文件名 `web_magiclicense.db`。
客户端窗口 Ctrl+C 可停止独立演示宿主。

## Linux

安装 JDK 17+，在解压目录运行：

```sh
sh run.sh setup
sh run.sh server
# 在浏览器完成上述步骤 3–4；另一个终端运行：
sh run.sh license
sh run.sh client
```

基础版无平台原生依赖，基础版和原生版系统流程均已通过 Windows/Linux 测试，Windows 包内 PowerShell 初始化/启动/发证/客户流程也已实测。
实际主机仍须验收 JDK、所有权、证书和防火墙。
Linux 启动其他程序使用 sh run.sh client localhost:13331 MyApp 1.0.0。

## 包结构及后续启动

```text
SkyLicense-Basic/
  SkyLicense-Server.jar
  SkyLicense-basic.jar
  DemoApp-1.0.0.jar
  SetupLocal.java / SetupLocal.ps1 / run.sh
  StartServer.ps1 / MakeLicense.ps1 / StartClient.ps1
  runtime/                       # 一次性生成，服务端专属数据和密钥
  customer/                      # 一次性生成，客户授权文件、密钥和持久化状态
```

从包目录运行脚本，脚本自动进入 runtime/customer。Web 是 HTTPS 18443，客户端认证是 TLS TCP 13331，
客户地址不能带 https:// 或误用 18443。服务端 runtime 不能交给客户，ZIP 没有预置许可证、真实配置或通用管理员密码。
如果初始化中途失败，先保留已生成目录排查，不能盲目覆盖。

## 接入自己的程序

上传的 JAR 根目录包含 `settings.yml`，例如：

```yaml
Name: MyApp
Version: 1.0.0
EntryClass: example.Entry
EntryPoint: start
InfPort: false
KeepClasses: []
```

入口必须是 `public static void start()` 这样的公开静态无参数方法，初始化后及时返回。
JAR 最多 64 MiB；Name/Version 与后台及客户端参数完全一致。普通资源文件目前不随受保护类协议下发，
配置/图片等非 class 资源放在客户宿主 classpath 或数据目录中。代码依赖库也需要在宿主 classpath 中。
反射框架敏感类可用 KeepClasses 正则排除方法改写，仍然加密下发。

Windows 启动自定义程序：

```powershell
.\StartClient.ps1 -Program MyApp -Version 1.0.0
```

Java 宿主的接入方式是实现 SDK 的 `PluginProxy` 六个方法，然后调用：

```java
BasicLicenseClient client = new BasicLicenseClient(proxy);
Response result = client.authenticate("license.example.com:13331", "MyApp", "1.0.0");
if (result != Response.ACCEPT) {
    throw new IllegalStateException("Authentication failed: " + client.getLastError());
}
// SDK 已调用业务入口。保留 client，宿主结束时调用 client.close()。
```

类位于 `cn.sky.license`，运行需 Java 17+。宿主 `disablePlugin()` 必须真正停用业务；独立 BasicLauncher 会退出进程。
一个 JVM 同时仅允许一个基础版活跃会话，失败后优先修复原因并重启宿主。SDK 返回 ACCEPT 前已经执行入口，
入口异常/ACK 失败可能已消耗当日额度。

## 密钥、绑定和远程部署

- `customer/secrets/license-file-secret.txt` 是每个客户独立的授权文件密钥。生成和读取 license.dat 必须使用同一个值。
  新客户重新运行 `java -cp SkyLicense-basic.jar SetupLocal.java client <新客户目录>`，不要共享所有客户的密钥。
- `customer/customer-data/basic-installation.id` 是持久化的随机部署标识。保留该文件才能保留绑定；更换/删除会产生新绑定。
  它不是硬件指纹，复制数据目录可能复制身份；基础版不承诺硬件防克隆或反破解。
- Build ID 是基础 SDK 版本标记，不是原生签名证明。当前基础版白名单值为
  `7f10d350d700568181fc244d4f3b779c75ab57316ae8e0e573a1802b815c33f0`，epoch 为 1。
- 初始化证书仅包含 localhost/127.0.0.1，30 天到期。跨机器部署需换成实际域名证书，并同步
  runtime/config.json 的 authTlsServerName，客户端使用该域名；不能直接用远程 IP 连接 localhost 证书。
- 公共 CA 证书默认使用 JVM 信任库：直接 Java 启动时不设置 `SKYLICENSE_BASIC_CA_CERT_FILE`。
  私有 CA 用该变量指向相应 PEM 文件。可额外设置 `SKYLICENSE_BASIC_CERT_SHA256` 为 TLS 叶证书 DER 的 SHA-256。
  随包 StartClient 脚本默认是本机测试配置；远程运行时应调整该脚本或按下面命令直接启动。

```powershell
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = 'C:\MyCustomer\secrets\license-file-secret.txt'
# 公共 CA 场景清除本机测试 CA 映射：
Remove-Item Env:\SKYLICENSE_BASIC_CA_CERT_FILE -ErrorAction SilentlyContinue
java -cp '.;SkyLicense-basic.jar' cn.sky.license.BasicLauncher license.example.com:13331 MyApp 1.0.0
```

## 备份与故障定位

后台验证日志区分封禁、到期、IP/部署绑定上限和每日额度。错误可同时查看客户 `failure stage`、
runtime/logs/latest.log 和健康探针 `https://localhost:18443/health/ready`。
修改管理员密码/MFA 后需要重新登录；管理员未完成 MFA 时业务 API 的 403 是正常限制。

停服务后，以运行账号进入 runtime，提供原审计/MFA密钥文件和 `SKYLICENSE_BACKUP_HMAC_KEY_FILE`
（指向 `runtime/secrets/backup-hmac.txt` 的绝对路径），使用父目录服务端 JAR 执行：

```text
java -jar ../SkyLicense-Server.jar --create-backup <部署目录之外的私有目录>/backup.skybackup
java -jar ../SkyLicense-Server.jar --verify-backup <备份路径>/backup.skybackup
java -jar ../SkyLicense-Server.jar --extract-backup <备份路径>/backup.skybackup <全新恢复目录>
```

先把外部备份目录设置为 owner-only。新终端不会继承另一个 StartServer 终端的环境，必须明确映射原 operation-log-hmac.txt、
mfa-encryption-key.txt 和 backup-hmac.txt。归档有认证但没有加密，应使用加密备份存储。
归档不含 TLS 私钥和密钥文件，必须另行保存这些文件。恢复后修复 owner-only 权限、补回私钥及环境密钥，
运行 `--validate-config` 后再启动。目录和密钥由服务账号独占访问，不能直接公开到下载站。

完整服务端、Web、原生 SDK 和客户交付指南见 [仓库文档](https://github.com/SharkL0ve/SkyLicense#readme)。
