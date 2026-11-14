[English](README.md) | [简体中文](README.zh-CN.md)

# 受保护示例 DemoApp

## 构建、上传、运行

在仓库根目录执行：

```powershell
.\gradlew.bat basicExampleJar --no-daemon
```

Linux 使用 ./gradlew，产物为 build/basic-example/DemoApp-1.0.0.jar。
basicReleaseZip 也会包含该 JAR、服务端、SDK 和初始化脚本。

1. 按 [主流程](../../README.zh-CN.md) 启动服务端与 Web，登录并完成管理员 MFA。
2. 创建名称完全一致的 DemoApp 程序，上传 JAR，版本填 1.0.0。
3. 为程序签发许可证，使用客户独立密钥生成 license.dat。
4. 按 [SDK 指南](../../Client-Side/README.zh-CN.md) 运行 BasicLauncher 或 NativeLauncher。
5. 看到 Protected DemoApp started successfully. 和启动器成功/心跳信息，后台验证日志最终为 OK。
6. 封禁许可证确认宿主停用；解封后用新进程再次验证。

示例同时兼容两种 SDK。入口及时返回，由客户启动器维持租约，不要在入口永久阻塞。
另有 [系统测试程序](../../tools/fixtures/SmokeEntry.java)，覆盖继承、接口默认方法、协变返回、异常和密钥轮换后的分发。

## 制作自己的受保护 JAR

JAR 根目录包含唯一 settings.yml，示例配置见 [源文件](settings.yml)：

```yaml
Name: MyApp
Version: 1.0.0
EntryClass: example.Entry
EntryPoint: start
InfPort: false
KeepClasses: []
```

- 名称/版本与后台和客户端参数完全一致，长度 1–64，首位字母/数字，后续允许字母、数字、点、下划线、加号、连字符。
  上传首个版本后不能改程序名。
- JAR 不超过 64 MiB，入口类必须存在并提供公开静态无参数方法，如 public static void start()。
- 在 30 秒下发 ACK 窗口内完成初始化并返回，持续工作交给可管理的宿主/业务服务。
- 普通图片、配置等非 class 资源和外部依赖库不随本类协议下发，放客户宿主 classpath/数据目录。
  不要在宿主重复打包受保护入口类。
- KeepClasses 使用斜杠 JVM 类名的 RE2/J 正则；匹配类保留传输加密但跳过方法改写，适合少量反射/序列化敏感类。
  InfPort 是兼容字段，保持 false。
- 必须 Web/API 上传，不能直接复制到服务端 resources。

此示例展示入口执行，不是完整业务服务。正式宿主仍须落实 disablePlugin，退出时关闭 SDK。
