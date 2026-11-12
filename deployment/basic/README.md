[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense Basic 1.0.0

This package contains the server, embedded Web console, Java 17 SDK, protected example and local run scripts.
The TLS/v4 verification path includes policy checks, encrypted class delivery, entry execution, loading ACK,
signed heartbeats and online revocation. Native anti-debugging/memory protection are not included.

## Windows: first run

Install a full JDK 17 or 21. Extract the complete package to a writable directory and open PowerShell there.
Run all commands below from the extracted SkyLicense-Basic directory.

1. Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\SetupLocal.ps1`.
   Enter and confirm the initial admin password: 12–128 characters with at least three of uppercase, lowercase, digits and symbols.
   Setup creates private runtime/customer directories, independent random keys and a localhost certificate. Run it once;
   existing directories are not overwritten.
2. Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\StartServer.ps1` and keep the terminal open.
   Visit **https://localhost:18443/**. The generated self-signed certificate is for this local test;
   accept a browser exception for your own test server or trust that specific certificate in your personal store.
   The Java client explicitly loads it and still checks the hostname.
3. Log in as admin with the setup password. Change the password through the bottom-left account menu and log in again.
   Open Account Security (`账户安全`), enroll an authenticator, save the one-time recovery codes and log in again.
   Administrators must enroll MFA before business operations are available.
   After the administrator is created, delete runtime/secrets/bootstrap-admin.txt; later starts no longer map this credential.
4. Under Content Management → Programs (`内容管理 → 程序管理`), create **DemoApp**.
   Upload the included **DemoApp-1.0.0.jar** with version **1.0.0** and create a license for it.
   For an initial test choose one IP, one installation ID and no daily limit.
5. Open another terminal and run `powershell -NoProfile -ExecutionPolicy Bypass -File .\MakeLicense.ps1`.
   Enter the issued code at the prompt; it writes customer/license.dat without putting the code in command-line arguments.
6. Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\StartClient.ps1`.
   Success prints `Protected DemoApp started successfully.` and
   `License accepted; protected entry completed; heartbeat active.` The server authentication log ends in **OK**.
   Ban the license in the console: the next relevant heartbeat revokes it and the standalone client exits.

Type stop in the server terminal for graceful shutdown. On future runs use StartServer/StartClient; do not initialize again.
Preserve runtime/customer and their keys during upgrades, updating only application files/scripts.
The compatible database filename remains web_magiclicense.db. Ctrl+C stops the demonstration client.

## Linux

With JDK 17+ installed, run from the extracted directory:

```sh
sh run.sh setup
sh run.sh server
# Complete the console steps, then use another terminal:
sh run.sh license
sh run.sh client
```

The same Java implementation has no native platform dependency. Windows runtime tests passed;
Linux shell syntax was checked, but validate execution on your target Linux host.

## Your own application

The protected JAR must contain settings.yml at its root:

```yaml
Name: MyApp
Version: 1.0.0
EntryClass: example.Entry
EntryPoint: start
InfPort: false
KeepClasses: []
```

The public static no-argument entry must return promptly after initialization. Names/versions must exactly match the console and client arguments.
The JAR limit is 64 MiB. Upload it through the console rather than copying files into resources.
Non-class resources and dependency libraries must be available in the customer's host classpath/data directory.
KeepClasses accepts slash-separated RE2/J class patterns to skip method rewriting while retaining transport encryption.

```powershell
.\StartClient.ps1 -Program MyApp -Version 1.0.0
```

To use an existing host, implement cn.sky.license.PluginProxy and call BasicLicenseClient.authenticate(host, program, version).
Response.ACCEPT means the SDK already called the entry and received its server ACK; do not call the entry again.
Retain the client, keep the host running and close it during shutdown. disablePlugin must actually stop protected operations.
The packaged BasicLauncher exits its process on revocation. Only one Basic session can be active per JVM.

## Credentials, identity and remote servers

- Every customer needs an independent secret. Generate and read license.dat with the same SKYLICENSE_LICENSE_FILE_SECRET_FILE.
  To initialize another customer, run `java -cp SkyLicense-basic.jar SetupLocal.java client <new-directory>`.
- customer-data/basic-installation.id is a persistent random deployment identity, not a hardware fingerprint.
  Deleting it creates a new binding; copying a directory can copy the identity. Basic does not provide hardware anti-cloning or anti-debugging.
- The software version Build ID is `7f10d350d700568181fc244d4f3b779c75ab57316ae8e0e573a1802b815c33f0`, epoch 1.
  It is not native signature attestation.
- The setup certificate covers only localhost/127.0.0.1 and expires in 30 days.
  For a remote server, install an actual-domain certificate, update authTlsServerName, and use that domain in clients.
- A public-CA server uses the JVM CA store by default. For a private CA, set SKYLICENSE_BASIC_CA_CERT_FILE to its PEM file.
  SKYLICENSE_BASIC_CERT_SHA256 optionally pins the TLS leaf certificate's DER SHA-256.
  Packaged StartClient defaults to the local certificate; adjust it or launch directly for a remote public-CA deployment.

```powershell
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = 'C:\MyCustomer\secrets\license-file-secret.txt'
Remove-Item Env:\SKYLICENSE_BASIC_CA_CERT_FILE -ErrorAction SilentlyContinue
java -cp '.;SkyLicense-basic.jar' cn.sky.license.BasicLauncher license.example.com:13331 MyApp 1.0.0
```

## Operations and backups

Use authentication logs for bans, expiration, binding and daily quota failures. Quotas count resource releases, not heartbeats;
entry/ACK failure can consume quota. Application logs are in runtime/logs. Readiness is https://localhost:18443/health/ready.
Keep original audit/MFA/backup keys; never regenerate them on every restart. Password/MFA changes require a fresh Web login.

For offline backup, stop the server, enter runtime and supply the original audit/MFA credentials plus
SKYLICENSE_BACKUP_HMAC_KEY_FILE pointing to the absolute secrets/backup-hmac.txt path:

```text
java -jar ../SkyLicense-Server.jar --create-backup <private-directory-outside-runtime>/backup.skybackup
java -jar ../SkyLicense-Server.jar --verify-backup <backup-path>/backup.skybackup
java -jar ../SkyLicense-Server.jar --extract-backup <backup-path>/backup.skybackup <new-restore-directory>
```

Replace the placeholder paths. Archives exclude TLS private keys and environment secrets; save them separately.
Restore private files and owner-only permissions, then pass --validate-config before starting a restored deployment.
Do not distribute initialized runtime/customer directories or upload them to Git.
