[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense Java SDK

## 完整使用顺序

1. 按 [根目录流程](../README.zh-CN.md#从这里开始基础可用版) 启动服务端和 Web。
2. 上传 [受保护 JAR](../examples/basic-app/README.zh-CN.md)，为对应名称/版本签发许可证。
3. 准备客户独立的私有目录与授权文件密钥。
4. 交互生成 license.dat，再运行下方启动器。
5. 后台验证日志应为 OK；保持宿主运行并测试一次在线封禁。

SDK 会自行调用下发入口。不要把受保护入口重复打进客户宿主，也不要在 ACCEPT 后再调用一次。

## 选择和构建 SDK

| | 基础版 | 原生版 |
| --- | --- | --- |
| 客户 SDK | SkyLicense-basic.jar | SkyLicense.jar |
| 客户端类 | cn.sky.license.BasicLicenseClient | cn.sky.license.SkyLicense |
| 独立启动器 | cn.sky.license.BasicLauncher | cn.sky.license.NativeLauncher |
| 绑定身份 | 随机、持久化安装标识 | Windows/Linux 机器指纹 |
| 原生运行时防护 | 不包含 | 编译时选择，默认 Strict |
| 运行环境 | JDK 17/21，不依赖 DLL/SO | JDK 17/21、Windows/Linux x86-64、签名原生资产 |

仓库根目录执行：

```powershell
.\gradlew.bat :Client-Side:test :Client-Side:basicJar --no-daemon
```

Linux 使用 ./gradlew。基础版产物为 Client-Side/build/libs/SkyLicense-basic.jar；
[完整运行包](../deployment/basic/README.zh-CN.md) 还包含初始化脚本和 DemoApp。

原生 :Client-Side:jar 必须具备 Windows/Linux 两个平台的签名库、.integrity 清单及加固验证。
缺失资产导致打包失败属于预期门禁，不能通过关闭检查解决；正式发行按 [原生手册](../native/README.zh-CN.md) 执行受保护工作流。
两个 SDK JAR 包含重叠类，不要同时放进同一个 classpath。

## 准备客户目录及授权文件

客户目录归运行账号独占，不能与服务端数据混用：

```text
customer/
  SkyLicense-basic.jar            # 或 SkyLicense.jar
  license.dat
  secrets/license-file-secret.txt
  ca-cert.pem                    # 仅需要时提供公开证书/CA
  customer-data/                 # 首次运行创建，必须持久保留
```

每个客户使用独立密码学随机密钥，建议至少 32 字节随机值。本机运行包的 SetupLocal.ps1 / sh run.sh setup 会自动创建一份客户目录。
在解压包中，可用 java -cp SkyLicense-basic.jar SetupLocal.java client customer-b 初始化另一个客户；已有目标目录会拒绝覆盖。
手工部署使用凭据管理器并限制为 owner-only，不能误覆盖正在使用的密钥。

进入客户目录，生成和运行时选用同一个密钥：

```powershell
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = (Resolve-Path .\secrets\license-file-secret.txt).Path
java -cp .\SkyLicense-basic.jar cn.sky.license.LicenseFileTool .\license.dat
```

```sh
export SKYLICENSE_LICENSE_FILE_SECRET_FILE="$PWD/secrets/license-file-secret.txt"
java -cp ./SkyLicense-basic.jar cn.sky.license.LicenseFileTool ./license.dat
```

原生版把 JAR 名改为 SkyLicense.jar。按提示输入授权码，不要作为命令行参数。
文件使用带认证的 SKYLIC03 格式，必须位于 classpath 根目录；java -jar 不会自动包含当前目录。
_FILE 必须为绝对路径，不能同时设置 SKYLICENSE_LICENSE_FILE_SECRET 直接变量。

## 启动客户程序

以下命令均在客户目录执行。地址是 host:port，不带 https:// 或路径，使用认证端口（示例 13331），不是 Web 端口。
私有 CA 需设置相应变量为 PEM 绝对路径，公共 CA 则不设置该变量。

```powershell
# 基础版，本机初始化证书：
$env:SKYLICENSE_BASIC_CA_CERT_FILE = (Resolve-Path .\ca-cert.pem).Path
java -cp '.;SkyLicense-basic.jar' cn.sky.license.BasicLauncher localhost:13331 DemoApp 1.0.0 customer-data
```

```sh
export SKYLICENSE_BASIC_CA_CERT_FILE="$PWD/ca-cert.pem"
java -cp '.:SkyLicense-basic.jar' cn.sky.license.BasicLauncher localhost:13331 DemoApp 1.0.0 customer-data
```

原生版必须使用正式打包 SDK、实际服务器域名，并在服务端放行准确 Build ID：

```powershell
# 仅私有 CA 需要；公共 CA 时移除此映射：
$env:SKYLICENSE_NATIVE_CA_CERT_FILE = (Resolve-Path .\ca-cert.pem).Path
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -cp '.;SkyLicense.jar' cn.sky.license.NativeLauncher license.example.com:13331 MyApp 1.0.0 customer-data
```

```sh
export SKYLICENSE_NATIVE_CA_CERT_FILE="$PWD/ca-cert.pem" # 仅私有 CA
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -cp '.:SkyLicense.jar' cn.sky.license.NativeLauncher license.example.com:13331 MyApp 1.0.0 customer-data
```

私有 CA 不会跳过证书链、有效期、主机名或原生 Strict 编译 Pin。
基础版可额外设置 SKYLICENSE_BASIC_CERT_SHA256，为叶证书 DER 的 SHA-256。
原生 Pin 是构建期配置，不能在运行期改环境变量覆盖；更换证书可能需要重新发布 SDK。

成功显示 License accepted; protected entry completed; ... heartbeat active.，启动器持续运行。
认证失败退出码为 2，在线撤销退出码为 3。基础版约 20 秒心跳，原生约 30 秒，租约均为 90 秒。

## 嵌入已有 Java 宿主

实现 PluginProxy；仓库中的 [BasicLauncher.java](src/main/java/cn/sky/license/BasicLauncher.java) 和
[NativeLauncher.java](src/main/java/cn/sky/license/NativeLauncher.java) 是完整、可编译的宿主示例。

| 方法 | 宿主职责 |
| --- | --- |
| getDataFolder() | 私有、可写、持久化的 SDK 数据目录 |
| getResource(String) | 从宿主 classloader/resources 获取 license.dat |
| getResourceType() | 普通 license.dat 名称使用 Resource.CLEAR_LOWERCASE |
| isPrimaryThread() | 正确报告宿主主线程，并在合适线程认证 |
| info(String) | 输出 SDK 信息，不能附加密钥或授权码 |
| disablePlugin() | 真正停止受保护业务；独立宿主可退出进程 |

已经实现并创建 PluginProxy proxy 后的最小生命周期片段：

```java
import cn.sky.license.BasicLicenseClient;
import cn.sky.license.Response;

BasicLicenseClient client = new BasicLicenseClient(proxy);
Response result = client.authenticate("license.example.com:13331", "MyApp", "1.0.0");
if (result != Response.ACCEPT) {
    client.close();
    throw new IllegalStateException("License authentication failed: " + result);
}
Runtime.getRuntime().addShutdownHook(new Thread(client::close));
// 保留 client 到宿主关闭；SDK 已执行受保护入口。
```

原生接入将 BasicLicenseClient 替换为 SkyLicense，并导入 cn.sky.license.SkyLicense。
保留强引用、保持宿主运行，在关闭时调用 close()；isSessionActive() 查询租约，原生 getHeartbeatCount() 只统计有效签名 PONG。
一个 JVM 只允许一个原生桥，即使 close 后也不能重新创建以绕过终态；基础版同时只能有一个活跃会话。

原生会话撤销后的受保护调用抛出 SecurityException，普通业务异常正常传播。
仅在后台 disablePlugin 回调中打印日志或抛异常，不会自动停止其他线程；必须取消任务、关闭服务并禁止继续执行业务。

## 客户交付清单

- 仅交付宿主/SDK、客户专属 license.dat 和密钥、必要公开 CA，以及未下发的依赖和资源。
- 不能交付服务端数据库、TLS 私钥、审计/MFA/备份密钥或管理员凭据。
- settings.yml、后台版本和客户端参数的名称/版本必须一致，依赖放宿主 classpath。
- 保留基础版 customer-data/basic-installation.id；复制目录可能复制身份，它不提供硬件防克隆。
- 基础版切换原生版时使用新许可证或主动解绑旧安装，两者身份算法不同。
- 原生版确认 x86-64 JVM、正式签名/清单、TLS 编译 Pin，以及服务端 Build ID/epoch 白名单。
- 交付前实际测试 OK、错误/过期/封禁许可证及在线封禁。

## 故障排查

| 现象 | 检查 |
| --- | --- |
| 找不到 license.dat | classpath 包含客户根目录，PluginProxy 资源实现正确 |
| 授权文件认证失败 | 生成和运行使用相同客户密钥，格式为 SKYLIC03 |
| SOCKET_ERROR_CONNECT | 认证端口、防火墙、精确域名、CA/有效期/Pin、时钟 |
| CLIENT_BUILD_ERROR | Build ID/epoch 白名单与正确签名 SDK |
| HWID_ERROR | 原生机器标识可读，运行环境受支持 |
| NOT_ADDRESS | IP/HWID/安装标识绑定及上限；主动解绑，不要盲目删除数据 |
| DAILY_AUTH_LIMIT | 服务端自然日资源释放额度，心跳不计费 |
| BLACKLIST | 许可证到期/状态及有效封禁规则 |
| 入口错误、DELIVERY_ACK_ERROR | 入口和依赖正确，30 秒内返回；修复后重启 JVM |
| SESSION_ALREADY_INITIALIZED、SESSION_REVOKED | 不重复认证，不复用已进入终态的原生进程 |
| 原生加载失败 | 架构、库/清单完整性、私有可写数据目录、两个 JVM 参数 |

retry() 只是有限重试提示，不表示资源释放后仍可重试；不确定时先修复原因并重启宿主。入口/ACK 失败仍可能消耗资源释放额度。
测试入口为 :Client-Side:test，以及 Java 构建后的 python tools/local-smoke-test.py --basic / --native --build-native，详见 [验证报告](../VALIDATION.md)。
