[English](README.md) | [简体中文](README.zh-CN.md)

# Windows 服务部署

本机首次体验请在普通用户终端使用 [基础运行包](../basic/README.zh-CN.md)。
以下用于正式安装服务，先按 [服务端手册](../../src/README.zh-CN.md) 构建 JAR，并准备实际域名证书/私钥。
安装器会修改所选运行目录和备份目录的所有权/ACL，不能指向源码仓库或无关数据目录。

## 1. 准备文件与账号

- 使用专用低权限 gMSA（推荐）或本地服务账号，准备“作为服务登录”权限；gMSA 须允许目标主机使用。
- 安装 JDK 17/21。WinSW 不随仓库分发，须取得可信发行文件和经过独立确认的 SHA-256。
- 在 C:\ProgramData\SkyLicense 准备 SkyLicense-Server.jar、config.json、resources、certs/auth-chain.pem、certs/auth-key.pem。
- 复制本目录 SkyLicense.xml，修改其中 java.exe 路径。配置实际 TLS 域名、Web/认证端口和 SDK Build ID。
- secrets 中创建 operation-log-hmac.txt、mfa-encryption-key.txt、backup-hmac.txt，均为独立、固定、非零 64 位十六进制密钥。
- 首次启动准备 bootstrap-admin.txt，并取消 XML 中该 _FILE 映射的注释。只在第一次使用，不能长期保留。
- 全新部署可没有 web_magiclicense.db；升级恢复必须保留业务库及存在的 WAL/SHM sidecar、引用资源和固定密钥。

## 2. 安装与预检

从此模板目录在提权 PowerShell 执行安装器（服务运行本身不使用管理员）：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-SkyLicense.ps1 `
  -DeploymentRoot 'C:\ProgramData\SkyLicense' `
  -ServiceAccount 'CONTOSO\skylicense$' `
  -WinSWPath 'C:\staging\winsw-x64.exe' `
  -ExpectedWinSWSha256 '<经过确认的64位SHA256>'
```

替换占位路径和哈希。普通服务账号会安全提示密码；末尾为 $ 的 gMSA 不要求提供密码。
安装器校验 wrapper、配置服务身份，并把所选目录归给服务账号、移除其他主体的允许条目；不会自动启动服务。
不能给 Administrators、SYSTEM、Users、Everyone 添加允许条目来绕过应用的 owner-only 检查。
正式所有者必须是实际服务用户，不能是管理员组。

以服务账号、相同环境和运行目录执行 java -jar SkyLicense-Server.jar --validate-config，通过后通过受控服务管理流程启动 SkyLicense。
服务不会继承另一个交互终端临时设置的环境变量，须把 _FILE 映射保存在 SkyLicense.xml 中。
live 目录已由服务账号独占，后续更新使用独立 staging 和受控部署流程，不要直接把源码目录设为运行目录。

## 3. 首次 Web 登录

打开 https://证书域名:18443/（按配置端口调整），使用 admin 和初始密码登录。
改密码后重新登录，开启 TOTP 并保存恢复码，再验证第二个 MFA 管理员。
移除 XML 中 bootstrap 映射和源文件，重启一次确认不再提供初始化凭据。
加密 PEM 的 tls-key-password 映射仍需保留，不能随 bootstrap 一起删除。

## 4. 备份、恢复与升级

由相同服务/备份账号执行，按实际 JDK 路径调用：

```powershell
.\Backup-SkyLicense.ps1 -DeploymentRoot 'C:\ProgramData\SkyLicense' -BackupRoot 'C:\ProgramData\SkyLicenseBackups' -JavaPath 'C:\YourJdk\bin\java.exe'
```

脚本记录运行状态、正常停止服务、创建并验证部署目录外归档，原先在运行时才恢复启动。
安装器只授予该账号针对 SkyLicense 服务的查询/启动/停止权利。备份目录应位于加密卷并异地复制，归档本身仅认证、不加密。
恢复到新目录，补齐归档排除的 TLS 私钥和原环境凭据，修复所有权/ACL，预检通过后再切换服务。
升级前正常停服务并备份，不要强杀进程；保留配置、业务库、引用资源和原始密钥。

通过 HTTPS /health/live 与 /health/ready 监控，保留 CA/主机名验证；管理端口限制为可信来源。
应用日志位于 logs/latest.log，按 UTC 每天或 50 MiB 滚动；WinSW wrapper 日志有独立策略，须同时监控磁盘容量。
