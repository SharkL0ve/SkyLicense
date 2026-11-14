[English](README.md) | [简体中文](README.zh-CN.md)

# Deployment guide index

## Pick a deployment path

| Need | Guide |
| --- | --- |
| First working server + console + client on localhost | [Basic package](basic/README.md), or the [root quickstart](../README.md) |
| Dedicated Linux production service and scheduled backup | [systemd guide](linux/README.md) |
| Dedicated Windows production service and offline backup | [WinSW guide](windows/README.md) |
| Manual configuration, preflight and operations | [Server README](../src/README.md), [detailed deployment reference](../DEPLOYMENT.md) |
| Signed native SDK production release | [Native release guide](../native/README.md#production-release) |

Basic is an actual Java-only verification client, not an authentication mock. The native SDK adds runtime protections but requires its
own signed assets and release identity. Both talk to the same TLS/v4 server. Build the local package from repository root:

```powershell
.\gradlew.bat :test :Client-Side:test basicReleaseZip --no-daemon
```

On Linux use `./gradlew`. Extract `build/distributions/SkyLicense-Basic-1.0.0.zip` outside build/; never initialize a live deployment
in a generated build directory. The ZIP includes its own bilingual README and setup/start scripts.

## Production order

1. Prepare the real DNS name, matching TLS chain/private key, firewall rules and a dedicated non-admin/non-root service account.
2. Stage the server JAR, private resources directory and [config.example.json](config.example.json) renamed to config.json.
3. Generate/persist independent audit, MFA and backup keys; create the bootstrap password only for the first startup.
4. Apply owner-only permissions, map absolute credential files and run preflight as the service account.
5. Start the service, enroll administrator MFA, verify a second administrator, then remove bootstrap mapping/source.
6. Upload a protected JAR through Web, issue a license and complete the [customer SDK checklist](../Client-Side/README.md#customer-delivery-checklist).
7. Verify readiness, authentication `OK`, live revocation, audit integrity and a real offline backup/restore.

Local certificates and public CI identities are not production credentials. A deployment directory cannot be owned by root/an administrator
group as a shortcut to permissions. Runtime configuration, databases, customer licenses, keys and certificates are intentionally not committed.

## Upgrades and recovery

Gracefully stop before replacing server files or making offline backups. Preserve config, database, referenced resources and original
keys. Restore into a new directory, provision excluded TLS/private credentials separately, pass preflight, then switch the service.
Backups are authenticated but not encrypted; configure encryption, retention, external replication and restore drills separately.

See the [validation report](../VALIDATION.md) for the tested Windows/Linux workflows; deployment-specific certificates, service-manager
permissions and network policy still require acceptance testing on your target host.
