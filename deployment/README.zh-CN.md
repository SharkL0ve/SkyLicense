[English](README.md) | [简体中文](README.zh-CN.md)

# 部署文档索引

## 选择部署路径

| 需求 | 文档 |
| --- | --- |
| 本机首次跑通服务端、Web、客户端 | [基础运行包](basic/README.zh-CN.md)、[根目录流程](../README.zh-CN.md) |
| Linux 正式服务与定时备份 | [systemd 指南](linux/README.zh-CN.md) |
| Windows 正式服务与离线备份 | [WinSW 指南](windows/README.zh-CN.md) |
| 手工配置、预检与运维 | [服务端 README](../src/README.zh-CN.md)、[详细部署参考](../DEPLOYMENT.md) |
| 正式签名原生 SDK | [原生发布流程](../native/README.zh-CN.md#正式发布) |

基础版是完整的 Java 验证客户端，不是模拟认证；原生版额外提供运行时防护，但需正式签名资产和发行身份。
两者使用同一个 TLS/v4 服务端。在仓库根目录构建本机运行包：

```powershell
.\gradlew.bat :test :Client-Side:test basicReleaseZip --no-daemon
```

Linux 使用 ./gradlew。将 build/distributions/SkyLicense-Basic-1.0.0.zip 解压到 build 之外，不要在生成目录中初始化业务部署。
ZIP 内已包含独立中英文 README 和初始化/启动脚本。

## 正式上线顺序

1. 准备实际域名、匹配 TLS 证书/私钥、防火墙及非管理员/非 root 的专用服务账号。
2. 暂存服务端 JAR、私有资源目录，将 [config.example.json](config.example.json) 复制为运行目录的 config.json。
3. 生成并持久保存独立审计、MFA、备份密钥；首次启动才准备 bootstrap 密码。
4. 设置 owner-only 权限和凭据绝对路径，以服务账号预检。
5. 启动服务，完成管理员 MFA，验证第二管理员，再移除 bootstrap 映射及源文件。
6. Web 上传受保护 JAR，签发许可证，按 [客户交付清单](../Client-Side/README.zh-CN.md#客户交付清单) 接入 SDK。
7. 验证 ready、认证 OK、在线撤销、审计链及一次实际离线备份恢复。

本机证书和公开 CI 身份不能用于正式交付。不能把目录归给 root/管理员组来绕过安全配置。
运行配置、数据库、许可证、密钥和证书有意不提交到 Git。

## 升级与恢复

替换程序和离线备份前正常停服务，保留配置、业务库、数据库引用资源和原始密钥。
恢复到新目录，另行恢复不在归档内的 TLS 私钥/凭据，预检通过后再切换服务。
归档有认证但不加密，需额外配置加密存储、保留周期、异地复制和恢复演练。

[验证报告](../VALIDATION.md) 记录已通过的 Windows/Linux 流程；正式目标主机的证书、服务管理器权限和网络策略仍需验收。
