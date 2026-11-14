[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense server

## Start here

For a complete localhost installation, follow the [root quickstart](../README.md#getting-started-the-working-basic-edition).
It builds a package, generates private runtime files and a localhost certificate, starts this server with its bundled Web console,
and walks through publishing DemoApp and verifying a real license. Do not run the source checkout as a live deployment.

For a remote service, follow this order: build → provision a service account/TLS/keys → configure → preflight → start → enroll MFA
→ upload a program → issue a license → [connect a customer](../Client-Side/README.md).

## Build

Run from the repository root with a full JDK 17 or 21:

```powershell
# Windows
.\gradlew.bat :test :Client-Side:test bootJar --no-daemon --warning-mode all
```

```sh
# Linux
./gradlew :test :Client-Side:test bootJar --no-daemon --warning-mode all
```

The output is `build/libs/SkyLicense-Server.jar`. Node.js is not required unless changing the console;
the checked-in `src/main/resources/static/` is included in the JAR. Rebuild and synchronize the [Web module](../web/README.md)
before `bootJar` when changing frontend code. Rust and native signing material are not required for the server build.

## Runtime directory and configuration

Use a separate private directory owned by a dedicated, unprivileged service account:

```text
deployment-root/
  SkyLicense-Server.jar
  config.json
  certs/auth-chain.pem
  certs/auth-key.pem
  resources/
  secrets/                       # private credential files, or an external credential store
  web_magiclicense.db            # created on the first successful start
  logs/                          # created by the application
```

Start with [config.example.json](../deployment/config.example.json). Copy it as `config.json` only in the deployment directory.
All nine fields are required; unknown/duplicate fields are rejected. The example permits the Basic SDK Build ID.
For a native SDK, add its actual release Build ID and set a compatible minimum security epoch.

| Field | Configure it as follows |
| --- | --- |
| `debug` | `false` for deployment |
| `authPort` | Client TLS/v4 TCP port; example `13331` |
| `webPort` | HTTPS console/API port; example `18443`, not plaintext HTTP |
| `authTlsCertificateChain` | Leaf-first PEM certificate chain |
| `authTlsPrivateKey` | Matching PEM private key |
| `authTlsServerName` | Actual certificate-covered hostname/IP, without scheme, path or port |
| `minimumClientSecurityEpoch` | Positive minimum accepted SDK epoch |
| `allowedClientBuildIds` | Explicit list of accepted 64-character hexadecimal SDK Build IDs |
| `allowedWebOrigins` | `[]` for the bundled console; exact HTTPS Origins for a separate frontend |

Both listeners require TLS 1.3 and use the configured certificate/key. The localhost setup certificate is not valid for a remote domain.
The working directory, resource tree, database/sidecars and credentials must be owner-only; on Windows the owner must be the service
user, not the Administrators group. Do not add broad allow entries to bypass preflight. Use the
[Linux](../deployment/linux/README.md) or [Windows](../deployment/windows/README.md) service provisioning instructions.

## Persistent secrets

Prefer absolute `_FILE` paths. A direct variable and its `_FILE` variant must not both be set.
Credential files must be ordinary, owner-only UTF-8 files without links/reparse points in their paths; one terminal newline is allowed.

| Variable | Required when / contents |
| --- | --- |
| `SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE` | Every start; fixed independent nonzero 32-byte key encoded as 64 hex characters |
| `SKYLICENSE_MFA_ENCRYPTION_KEY_FILE` | Every start; another fixed independent 64-hex key |
| `SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE` | First start only; 12–128 characters, at least three character classes |
| `SKYLICENSE_TLS_KEY_PASSWORD_FILE` | Only for an encrypted TLS private key |
| `SKYLICENSE_BACKUP_HMAC_KEY_FILE` | Offline backup operations; independent fixed 64-hex key |
| `SKYLICENSE_OPERATION_LOG_MAX_ROWS_FILE` | Optional; default `500000`, accepted range `10000`–`10000000` |

Do not regenerate audit/MFA keys on restart. Back them up separately from the database. The customer license-file secret is a client
credential, not a required server setting. Production key provisioning and service-manager mappings are in [DEPLOYMENT.md](../DEPLOYMENT.md).

## Preflight, start and stop

Run as the service account, in the deployment directory, with the same credentials as the real service. PowerShell example:

```powershell
$env:SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE = 'C:\ProgramData\SkyLicense\secrets\operation-log-hmac.txt'
$env:SKYLICENSE_MFA_ENCRYPTION_KEY_FILE = 'C:\ProgramData\SkyLicense\secrets\mfa-encryption-key.txt'
# First start ONLY; remove this mapping after admin exists:
$env:SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE = 'C:\ProgramData\SkyLicense\secrets\bootstrap-admin.txt'
java -jar .\SkyLicense-Server.jar --validate-config
# Continue only after deployment_validation=ok:
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -jar .\SkyLicense-Server.jar
```

Linux uses `export NAME='/absolute/path'` and `./SkyLicense-Server.jar`; systemd should use `LoadCredential` instead of interactive exports.
Preflight does not create a missing database. Startup repeats validation, acquires `.skylicense.lock`, creates/migrates SQLite and opens
the authentication listener before making the Web service available. Do not start two processes against one deployment directory.

Open `https://<certificate-host>:<webPort>/`, log in as `admin`, change the initial password, then enroll TOTP under Account Security
and save recovery codes. Log in again. Remove the bootstrap mapping and its source file before the next start; an existing admin plus
a bootstrap variable is rejected. Create and verify a second MFA-enabled administrator for recovery.

For a foreground server, enter `stop`; for a service, use the service manager's stop operation. Do not use forced process termination
as the normal shutdown/upgrade method. Built-in commands are `help`, `online`, `refresh`, `reload`, `stop`; issuance is through Web/API.

## Publish and verify

1. In the [Web console](../web/README.md), create the final program name and upload a matching protected JAR.
2. The [example guide](../examples/basic-app/README.md) explains `settings.yml`, entry points and dependency placement.
3. Issue a license for that program, set expiration/binding/daily policy, and generate the customer-specific `license.dat`.
4. Start BasicLauncher or NativeLauncher using the [SDK guide](../Client-Side/README.md). `ACCEPT` means the SDK already executed the entry and confirmed ACK.
5. Confirm the authentication log ends in `OK`, then ban the license and verify the customer's host stops protected work.

Upload through Web/API: copying JARs into `resources/` does not publish versions. The database catalog is authoritative;
unreferenced JARs are quarantined and missing referenced files fail validation. Bindings/daily quota are committed at resource release;
entry or ACK failure can leave `DELIVERY_UNCONFIRMED` and does not refund the release. Quotas are not concurrent-session limits.

## Monitoring, backup and upgrades

Check `https://<host>:<webPort>/health/live` and `/health/ready` with normal certificate/hostname validation.
Readiness is `UP` only when the authentication listener, database and audit persistence are healthy; failure returns 503.
Logs are under `logs/latest.log` with UTC timestamps. The console's operation-log page verifies the audit chain.

Stop the service, retain the original audit/MFA keys, set the independent backup key, and run from the deployment directory:

```text
java -jar SkyLicense-Server.jar --create-backup <private-directory-outside-deployment>/backup.skybackup
java -jar SkyLicense-Server.jar --verify-backup <backup-path>/backup.skybackup
java -jar SkyLicense-Server.jar --extract-backup <backup-path>/backup.skybackup <new-restore-directory>
```

Replace placeholders. The archive is authenticated, not encrypted; use encrypted storage. It excludes TLS private keys and environment
credentials, which must be restored separately. Extract into a new directory, restore secrets/permissions, pass preflight, then switch
the service. Preserve live data, keys and resource catalogs during upgrades; database migrations are not a substitute for backup.

For 401/403, TLS, Build ID, binding and ACK problems, see the [SDK troubleshooting table](../Client-Side/README.md#troubleshooting),
[Web troubleshooting](../web/README.md#troubleshooting), [API reference](../API-DOC.md) and [validation report](../VALIDATION.md).
