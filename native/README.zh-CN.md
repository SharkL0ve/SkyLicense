[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense 原生客户端

本目录现在使用新版 **SkyLicense-Client**，不是之前的 v2 旧版。
原生发行资产目前面向 x86-64 Windows 和 Linux。
实现当前服务端的 TLS 1.3 / v4 认证、X25519/HKDF 挑战、AES-GCM 资源和方法下发、加载 ACK、签名心跳与单调时钟租约撤销。
如需最简单的 Java 基础版使用流程，请先阅读 [根目录中文 README](../README.zh-CN.md)。

## 真实本地联调

命令均在仓库根目录执行。准备 JDK 17/21、Python 3.10+ 与固定的 Rust 1.97.1。
Windows 另需 Visual Studio MSVC C++ Build Tools 和 Windows SDK：

```powershell
rustup target add x86_64-pc-windows-msvc --toolchain 1.97.1
.\gradlew.bat test :Client-Side:test bootJar --no-daemon
python -m pip install cryptography
python tools/local-smoke-test.py --native --build-native
```

Linux 使用原生 GNU Rust 目标，并安装 C 编译器和 binutils：

```sh
./gradlew test :Client-Side:test bootJar --no-daemon
python3 -m pip install cryptography
python3 tools/local-smoke-test.py --native --build-native
```

脚本构建严格模式 TLS 原生库，签署并验证 CI 测试清单，检查 PE/ELF 加固，然后部署真实服务端、完成 MFA、上传受保护程序、签发测试许可证，
通过 Java SDK 的正常原生提取/加载流程执行程序。程序源码为 [SmokeEntry.java](../tools/fixtures/SmokeEntry.java)，
包含继承、接口默认方法、协变返回和整数返回，并在密钥轮换后再次调用受保护代码。
还会检查拒绝策略、缺失/篡改清单、在线撤销、宿主停用通知、审计及备份恢复。

成功时最后显示 web_smoke=PASS。日志、随机凭据和证书仅保留在新的私有临时目录，不触碰现有部署；结束时关闭测试服务端。
公开 CI 身份仅用于测试。需要指定其他已安装编译器或目标时，使用 --rust-toolchain 或 --native-target。

## 客户程序接入

按根目录流程上传程序 JAR、签发许可证，并使用客户独立的 SKYLICENSE_LICENSE_FILE_SECRET_FILE 生成 license.dat；宿主读取时使用相同密钥文件。
license.dat 必须位于宿主类路径根目录。仓库自带的 [DemoApp](../examples/basic-app/src/example/Entry.java) 可用于基础版或原生版。
取得正式签名并打包好的 SkyLicense.jar 后，启动独立原生宿主：

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

详见 [安全说明](SECURITY.md) 和 [部署手册](../DEPLOYMENT.md)。原项目署名：Client of MagicLicense, by pi_ka。
