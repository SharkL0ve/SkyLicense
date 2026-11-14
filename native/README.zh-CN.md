[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense 原生客户端

本目录是统一仓库中当前启用的 **SkyLicense-Client** Rust JNI 模块。
原生发行资产目前面向 x86-64 Windows 和 Linux。
实现当前服务端的 TLS 1.3 / v4 认证、X25519/HKDF 挑战、AES-GCM 资源和方法下发、加载 ACK、签名心跳与单调时钟租约撤销。
如需最简单的 Java 基础版使用流程，请先阅读 [根目录中文 README](../README.zh-CN.md)。

## 应该选择哪条流程

- 验证当前源码：运行下方隔离联调，脚本自动生成测试身份和配置。
- 接入 Java 应用：阅读 [Java SDK README](../Client-Side/README.zh-CN.md)，业务应用不直接调用 Rust 库。
- 正式交付客户：完成下方受保护发布，本机 CI 测试 DLL/SO 不是正式发行包。

搭配本仓库当前服务端使用；认证地址是 TLS/v4 TCP 的 host:authPort，不是 Web HTTPS API。
Windows/Linux 原生运行流程均已真实测试通过，范围见 [验证报告](../VALIDATION.md)。

## 真实本地联调

命令均在仓库根目录执行。准备 JDK 17/21、Python 3.10+ 与固定的 Rust 1.97.1。
Windows 另需 Visual Studio MSVC C++ Build Tools 和 Windows SDK：

```powershell
rustup target add x86_64-pc-windows-msvc --toolchain 1.97.1
.\gradlew.bat test :Client-Side:test bootJar --no-daemon
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install cryptography
.\.venv\Scripts\python.exe tools/local-smoke-test.py --native --build-native
```

Linux 使用原生 GNU Rust 目标，并安装 C 编译器和 binutils：

```sh
./gradlew test :Client-Side:test bootJar --no-daemon
python3 -m venv .venv
. .venv/bin/activate
python -m pip install cryptography
python tools/local-smoke-test.py --native --build-native
```

脚本构建严格模式 TLS 原生库，签署并验证 CI 测试清单，检查 PE/ELF 加固，然后部署真实服务端、完成 MFA、上传受保护程序、签发测试许可证，
通过 Java SDK 的正常原生提取/加载流程执行程序。程序源码为 [SmokeEntry.java](../tools/fixtures/SmokeEntry.java)，
包含继承、接口默认方法、协变返回和整数返回，并在密钥轮换后再次调用受保护代码。
还会检查拒绝策略、缺失/篡改清单、在线撤销、宿主停用通知、审计及备份恢复。

成功时最后显示 web_smoke=PASS。日志、随机凭据和证书仅保留在新的私有临时目录，不触碰现有部署；结束时关闭测试服务端。
公开 CI 身份仅用于测试。需要指定其他已安装编译器或目标时，使用 --rust-toolchain 或 --native-target。
构建 bootJar 后，可先运行 python tools/local-smoke-test.py --preflight-only 快速预检，无需等待原生构建。
所有 Python 命令均使用相应虚拟环境解释器，Windows 上方命令无需修改激活脚本执行策略。
完整原生联调还需要 Client-Side:classes，上方 Java 构建会生成。不能对客户正在使用的数据库执行源码测试。

根目录工作区统一管理工具链、锁文件、构建 profile 和平台参数；Cargo 命令从仓库根目录运行。
cargo fmt --all --check 不需要发行密钥；Clippy 和 cargo test 会编译身份门禁，需要与 CI 相同的身份环境。
测试环境参考 [native-security-ci.yml](../.github/workflows/native-security-ci.yml)，但不能把公开测试身份当成生产签名凭据。

## 客户程序接入

按根目录流程上传程序 JAR、签发许可证，并使用客户独立的 SKYLICENSE_LICENSE_FILE_SECRET_FILE 生成 license.dat；宿主读取时使用相同密钥文件。
license.dat 必须位于宿主类路径根目录。仓库自带的 [DemoApp](../examples/basic-app/src/example/Entry.java) 可用于基础版或原生版。
取得正式签名并打包好的 SkyLicense.jar 后，启动独立原生宿主：

先进入同时含 SDK 和 license.dat 的客户目录，将 SKYLICENSE_LICENSE_FILE_SECRET_FILE 设置为客户私有密钥文件绝对路径。
业务依赖和未下发的资源也须位于宿主 classpath。

```powershell
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -cp ".;SkyLicense.jar" cn.sky.license.NativeLauncher license.example.com:13331 MyApp 1.0.0 customer-data
```

Linux 将类路径改为 '.:SkyLicense.jar'。私有 CA 部署设置 SKYLICENSE_NATIVE_CA_CERT_FILE 为 CA PEM 的绝对路径；公共 CA 可不设置。
证书链、有效期、主机名与严格模式编译时 Pin 始终验证，没有信任所有证书的开关。
服务端必须放行该 SDK 的准确 Build ID 与 security epoch。
从基础版切换到原生版时，请使用新许可证或先解绑旧安装：二者的绑定标识算法不同。

嵌入宿主实现 PluginProxy，调用 new SkyLicense(proxy).authenticate(...)，持有客户端，并真正落实 disablePlugin() 来停止受保护业务，退出时调用 close()。
isSessionActive() 查询原生租约，getHeartbeatCount() 仅统计已认证 PONG。每个 JVM 只允许一个原生桥接；成功后的重复认证不会再次释放资源。
租约到期或撤销后，受保护调用抛出 SecurityException，Java 监控也会通知宿主停用。

## 正式发布

Cargo 配置、锁文件和 Rust 工具链由仓库根目录统一管理。
在本仓库配置受保护环境，使用根目录 release-native 和 package-sdk-release 工作流：前者构建本目录的 Windows/Linux 原生资产，后者从本仓库 Release 下载并验证。
正式发布必须使用自己的 TLS 证书/Pin、Ed25519 身份、Build ID/epoch 和可信 Windows Authenticode 材料。
禁止交付测试证书、公开 CI 私钥种子或固定 CI Build ID；正式打包门禁未被关闭。

1. 在 GitHub 配置 native-production 受保护环境及审核人，设置下表变量/Secret。
2. 运行 [release-native](../.github/workflows/release-native.yml)，输入全新 tag、随机 Build ID、当前 epoch 和最低 epoch。
   Windows 使用原生 MSVC，先 Authenticode 后清单；Linux 完成最终 strip 后再签清单。
3. 确认 Release 包含 SkyLicense_64.dll、libSkyLicense_64.so、两个 .integrity、SHA256SUMS 和 native-release.json。
4. production-sdk 环境设置相同公钥和 Windows 签名证书指纹，运行 [package-sdk-release](../.github/workflows/package-sdk-release.yml)，
   选择对应原生 tag，并使用完全相同的身份参数。
5. 从正式 SDK Release 获取 SkyLicense.jar、校验和及 provenance，交付前在服务端放行该 Build ID。

| 配置 | 环境及含义 |
| --- | --- |
| SKYLICENSE_MANIFEST_PUBLIC_KEY | 两个环境；原始 Ed25519 公钥，64 位十六进制 |
| SKYLICENSE_MANIFEST_PRIVATE_KEY | 仅 native-production Secret；独立私钥种子，不能交付 |
| SKYLICENSE_CERT_SHA256 | native-production 变量；实际 TLS 叶证书 DER 的 SHA-256 |
| SKYLICENSE_CERT_SHA256_NEXT | 可选下一张证书 Pin，必须与已设置主 Pin 不同 |
| WINDOWS_CODESIGN_CERT_SHA256 | 两个环境；Authenticode 证书 DER SHA-256，不是 TLS Pin 或 SHA-1 指纹 |
| WINDOWS_CODESIGN_PFX_BASE64 / WINDOWS_CODESIGN_PASSWORD | native-production Secrets |
| WINDOWS_CODESIGN_TIMESTAMP_URL | native-production 变量；可信时间戳服务 |

Build ID/epoch 通过工作流输入，不能混用生产和测试身份，也不会覆盖已存在 tag。
精确门禁和资产名以工作流为准；普通 push 不会自动发布正式原生 SDK。

证书轮换顺序：先发“旧主 Pin + 新次 Pin”的 SDK 并升级客户，再切换服务端证书，最后发仅保留新主 Pin 的清理版。
私有 CA 场景同时准备好相应信任链。

## 运行限制及排查

Strict 是默认不可变编译 profile；Balanced/Compatible 必须明确选择，见 [安全说明](SECURITY.md)。
不要降低 profile、关闭签名或 TLS 来绕过配置错误。缺 JVM 参数、清单不匹配、Pin 过期、Build ID 未放行、数据目录权限不安全，均应修复根因。
原生防护不能让管理员/root 控制的机器变可信，机器指纹也不是硬件证明。
宿主须保持心跳，并真正执行 disablePlugin 停止业务，详见 [SDK 排查](../Client-Side/README.zh-CN.md#故障排查)。

详见 [安全说明](SECURITY.md) 和 [部署手册](../DEPLOYMENT.md)。原项目署名：Client of MagicLicense, by pi_ka。
