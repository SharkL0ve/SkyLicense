[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense Rust 原生客户端

需要正常使用验证系统，请先阅读根目录 [基础可用版使用流程](../README.zh-CN.md)。该版本无需原生库即可完成 TLS/v4 验证。

本目录保留原 MagicLicense-Client 的源码，现已纳入根目录 Cargo 工作区，统一使用根目录 Cargo.lock。
服务端、Java SDK 和 Vue 前端也在同一个仓库中维护。

## 兼容性边界

- src/lib.rs 的认证仍通过普通 TcpStream 发送协议版本 2。
- 当前服务端要求 TLS 1.3、协议 4、发布身份、挑战和加载 ACK。
- 此份源码没有配套的 v4 签名发布工作流及清单。
- 编译成功或原生单元测试通过，不代表它能与当前服务端完成认证。

**不要将本目录构建出的 DLL/SO 覆盖到当前 SDK。** 正式 SDK 的打包验证门禁继续保留。
恢复匹配的 v4 实现、验收 Windows/Linux 原生加固属于后续独立工作，此次仅合并整理源码。

## 开发测试

安装支持 edition 2024 的 Rust 工具链，在仓库根目录运行：

```sh
cargo test --workspace --locked
cargo check --workspace --locked
```

可选的旧版构建命令为 cargo build --release --locked，不是基础可用版的构建入口。
产物位于根目录 target；Windows GNU 链接映射输出为 SkyLicense.map，并已忽略。
保留原项目 release 配置，不导入二进制、构建缓存、凭据或嵌套 Git 仓库。
Rust 源码已恢复为合并前备份中的原始旧版，取消本次 v4 协议升级。
原始测试共享全局 XOR 密钥，并行时可能相互干扰；此旧版行为同样原样保留。

Java 基础包独立使用 gradlew basicReleaseZip 构建，Windows 对应 gradlew.bat。
前端开发及部署说明见 [根目录中文 README](../README.zh-CN.md)。

原项目署名：Client of MagicLicense, by pi_ka。
