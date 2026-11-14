[English](README.md) | [简体中文](README.zh-CN.md)

# Linux 服务部署

首次本机体验使用 [基础运行包](../basic/README.zh-CN.md)。以下为正式专用服务流程，
先按 [服务端 README](../../src/README.zh-CN.md) 构建 JAR，并准备实际域名 TLS 和固定密钥。
模板文件名相关命令从源码 deployment/linux 目录执行；已有部署必须先做可验证备份，不能当作全新安装覆盖。

## 1. 准备账号和目录

模板使用 /opt/skylicense、专用账号 skylicense、/usr/bin/java（JDK 17/21）。
目标 systemd 必须支持模板中的 LoadCredential 等指令，上线前使用 systemd-analyze verify 检查。
首次安装：

```bash
sudo useradd --system --home /opt/skylicense --shell /usr/sbin/nologin skylicense
sudo install -d -o skylicense -g skylicense -m 700 /opt/skylicense
sudo install -d -o skylicense -g skylicense -m 700 /opt/skylicense/certs /opt/skylicense/resources
sudo install -d -o root -g root -m 700 /etc/skylicense/credentials
sudo install -d -o skylicense -g skylicense -m 700 /var/backups/skylicense
sudo install -d -o root -g root -m 755 /usr/local/libexec
sudo install -o root -g root -m 755 skylicense-backup /usr/local/libexec/skylicense-backup
```

把 SkyLicense-Server.jar、config.json 放入 /opt/skylicense，证书/私钥放 certs，文件归 skylicense、权限 600，目录 700。
配置实际域名、Web/认证端口与 SDK Build ID，不要直接使用占位值。新部署可以没有数据库；升级须保留已有业务库、资源和密钥。

## 2. 准备固定凭据

通过受控密钥工具在 /etc/skylicense/credentials 创建 root 所有、600 的文件：

| 文件 | 内容 |
| --- | --- |
| operation-log-hmac | 独立、固定、非零 64 位十六进制密钥 |
| mfa-encryption-key | 另一份独立、固定 64 位十六进制密钥 |
| backup-hmac | 独立固定备份密钥，供备份单元使用 |
| bootstrap-admin-password | 仅首次启动，12–128 位、至少三类字符的密码 |

LoadCredential 由 systemd 提供服务可访问的私有副本，应用只接收 _FILE 路径。
不能把密钥内容写进 unit、命令行或仓库，也不能在升级时重新生成。
加密 PEM 的 tls-key-password 映射应放独立持久 drop-in，不能与之后要删除的 bootstrap 文件混在一起。

## 3. 首次启动

先准备 bootstrap 凭据，再安装服务和临时 drop-in：

```bash
sudo install -m 644 skylicense.service /etc/systemd/system/skylicense.service
sudo install -d -m 755 /etc/systemd/system/skylicense.service.d
sudo install -m 644 skylicense-bootstrap.conf.example /etc/systemd/system/skylicense.service.d/10-bootstrap.conf
sudo systemctl daemon-reload
sudo systemctl enable --now skylicense.service
sudo systemctl status skylicense.service
```

ExecStartPre 会以实际服务身份和凭据执行 --validate-config；失败时检查 sudo journalctl -u skylicense.service -n 100，不能关闭预检。
打开 https://证书域名:18443/（端口按配置），修改初始密码，完成 MFA，再验证第二管理员。
删除临时 10-bootstrap.conf 和 bootstrap 源凭据，执行 daemon-reload 后重启一次清除进程环境。
已有管理员时仍映射 bootstrap 会被拒绝。

## 4. 备份及运维

先验证手工备份成功，再启用定时任务：

```bash
sudo install -m 644 skylicense-backup.service /etc/systemd/system/skylicense-backup.service
sudo install -m 644 skylicense-backup.timer /etc/systemd/system/skylicense-backup.timer
sudo systemctl daemon-reload
sudo systemctl start skylicense-backup.service
sudo systemctl enable --now skylicense-backup.timer
```

备份单元先停止主服务，创建并验证部署目录外的归档，仅当原先正在运行时才恢复启动。
计划时间为 UTC 02:15，另有最多 15 分钟随机延迟，不是本地时区 02:15。
归档不加密，须另行配置加密卷、保留周期和异地复制。
恢复到新目录，独立恢复 TLS 私钥和凭据，通过预检再切换服务；不能让两个实例使用同一个业务库。

监控 HTTPS /health/live 和 /health/ready，保留 CA/主机名验证。管理端口限制为可信管理和监控来源。
日志位于 /opt/skylicense/logs/latest.log，UTC 时间，每天或 50 MiB 滚动；检查磁盘和集中日志保留策略。
升级使用 systemctl stop skylicense 正常停机，保留 config、数据库、引用资源和固定密钥，不要 kill -9。
