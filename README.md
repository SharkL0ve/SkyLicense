[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense

A license server, management console and Java SDK for delivering protected Java applications over TLS 1.3.

Follow the complete first-run workflow below: server → Web console → protected JAR → license file → client.
Use Basic for a first installation; use the signed native SDK when you need its additional runtime protections.

| Component | Read this next |
| --- | --- |
| Server configuration, accounts and operations | [Server README](src/README.md) |
| Web console, frontend build and HTTPS development | [Web README](web/README.md) |
| Java Basic/native SDK and customer integration | [Java SDK README](Client-Side/README.md) |
| Rust native builds, release identity and platform checks | [Native README](native/README.md) |
| Protected application JAR | [Example README](examples/basic-app/README.md) |
| Local package and production services | [Deployment index](deployment/README.md) |

See [validation results](VALIDATION.md) for tested scope and remaining limits. A passing test build is not a production native release.

## Getting started: the working Basic edition

Basic implements the complete online verification path without DLLs: license checks, encrypted class delivery,
entry-point execution, loading acknowledgement, signed heartbeats and online revocation.
Basic intentionally excludes native anti-debugging, anti-dump and memory protection; these belong to the separate native SDK.
Basic's installation ID is not a hardware fingerprint.

### 1. Build the runnable package

Install a full **JDK 17 or 21** (`java`, `javac` and `keytool` must be available) and clone this repository.
Use a normal user terminal, not an elevated administrator/root terminal, for the local demo:

```sh
git clone https://github.com/SharkL0ve/SkyLicense.git
cd SkyLicense
```

Windows PowerShell:

```powershell
.\gradlew.bat :test :Client-Side:test basicReleaseZip --no-daemon --warning-mode all
```

Linux:

```sh
./gradlew :test :Client-Side:test basicReleaseZip --no-daemon --warning-mode all
```

Extract `build/distributions/SkyLicense-Basic-1.0.0.zip` to a separate writable run directory.
Do not store a live database under `build/`. The package contains the server, embedded console, Java SDK,
protected example JAR and setup/run scripts. No runtime configuration or credentials are checked into Git.

### 2. Initialize and start the server

From the extracted `SkyLicense-Basic` directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\SetupLocal.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\StartServer.ps1
```

Enter and confirm the initial administrator password: 12–128 characters, including at least three of uppercase letters,
lowercase letters, digits and symbols. Setup creates private `runtime/` and `customer/` directories, independent random keys,
a localhost TLS certificate and the Basic SDK allowlist. **Run setup once**; existing directories are never overwritten.

Keep the server terminal open and visit **https://localhost:18443/**. Client authentication uses **localhost:13331**.
The generated self-signed certificate covers only localhost/127.0.0.1 and expires in 30 days.
For this local test, use your browser's certificate exception or trust this specific certificate in your personal store.
The Java launcher explicitly trusts this certificate and still verifies the hostname.

### 3. Initialize the administrator

1. Log in as `admin` using the password entered during setup.
2. Open the bottom-left account menu, change the password, and log in again.
3. Open Account Security (`账户安全`), enter the current password, scan the authenticator QR code and submit its six-digit code.
4. Save the recovery codes shown once, then log in again using TOTP or an unused recovery code.
5. After the administrator exists, delete `runtime/secrets/bootstrap-admin.txt`. Subsequent starts do not map this one-time credential.

Administrators must enroll MFA before business APIs are available. HTTP 403 for an enrollment-only administrator is expected.
Create and verify a second MFA-enabled administrator for account recovery. The console currently uses Chinese labels;
the relevant labels are included in this guide.

### 4. Publish the example and issue a license

1. Under Content Management → Programs (`内容管理 → 程序管理`), create **DemoApp**.
2. Open the program, upload the included **DemoApp-1.0.0.jar**, and enter version **1.0.0**.
3. Create a license. For the first test, choose one IP, one installation ID and no daily limit.
4. In another terminal in the extracted directory, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\MakeLicense.ps1
```

Enter the issued license at the prompt. The tool writes `customer/license.dat` in authenticated `SKYLIC03` format;
the code is not a command-line argument. Use an interactive terminal for hidden input; redirected or IDE input may not hide echo.

### 5. Start the client and test revocation

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\StartClient.ps1
```

Expected output:

```text
Protected DemoApp started successfully.
License accepted; protected entry completed; heartbeat active.
```

The console authentication log must end in **OK**. The client stays alive and sends a heartbeat approximately every 20 seconds.
Ban its license in the console: a subsequent signed heartbeat revokes the session and stops the standalone client.
Type `stop` in the server terminal for graceful shutdown. On later runs, use StartServer/StartClient directly; do not initialize again.

### Linux commands

In the extracted package:

```sh
sh run.sh setup
sh run.sh server
# Complete the console steps, then use another terminal:
sh run.sh license
sh run.sh client
```

Both Basic and the Strict native workflow passed real Windows/Linux system tests. The packaged PowerShell launch scripts were
also tested on Windows; validate the service-account, certificate and filesystem setup on each deployment host.

### 6. Move the client to another computer

Do not copy the initialized server `runtime/` directory to a customer. Deliver the launcher/SDK, `license.dat`,
that customer's independent license-file secret, and only the public CA certificate when needed.
Replace the localhost server certificate with one covering the real domain, update `authTlsServerName`, and expose the configured
authentication port. The client endpoint is `license.example.com:13331`, not an HTTPS URL and not the Web port.
See the [SDK customer-delivery checklist](Client-Side/README.md#customer-delivery-checklist) before distribution.

## Integrate your own application

Put `settings.yml` at the protected JAR root:

```yaml
Name: MyApp
Version: 1.0.0
EntryClass: example.Entry
EntryPoint: start
InfPort: false
KeepClasses: []
```

The entry must be a public static no-argument method, such as `public static void start()`.
Initialize the application and return promptly so the loading ACK can complete. Program name, upload version and client arguments
must match `Name`/`Version` exactly, including case. Names/versions are 1–64 safe ASCII characters: a letter/digit first,
then letters, digits, `.`, `_`, `+` or `-`. The JAR limit is 64 MiB. A program cannot be renamed after its first version is uploaded.

Publish through the console: copying a file into `resources/` does not create a version catalog entry. Uncataloged files are quarantined.
Ordinary non-class resources and dependency JARs belong in the customer's host classpath/data directory.
`KeepClasses` accepts RE2/J patterns over slash-separated JVM names; matching classes stay encrypted in transit but skip method rewriting.

Run a different program with the packaged host:

```powershell
.\StartClient.ps1 -Program MyApp -Version 1.0.0
```

For an existing Java host, implement all six methods of `cn.sky.license.PluginProxy`, then call (imports and lifecycle are documented
in the [SDK README](Client-Side/README.md)):

```java
BasicLicenseClient client = new BasicLicenseClient(proxy);
Response result = client.authenticate("license.example.com:13331", "MyApp", "1.0.0");
if (result != Response.ACCEPT) {
    throw new IllegalStateException("Authentication failed: " + client.getLastError());
}
// The SDK already invoked the entry. Retain client, keep the host alive,
// and call client.close() when the host shuts down.
```

`disablePlugin()` must actually stop protected business operations. `BasicLauncher` exits its process for this purpose.
Only one Basic session can be active in a JVM. Fix delivery/rejection errors before restarting the host; do not invoke the entry twice.

## Policy and customer credentials

| Setting | Meaning |
| --- | --- |
| IP / installation limit | `0` is unlimited; positive values limit distinct bindings, not concurrent sessions |
| Expiration | Blank is permanent; API format is `yyyy-MM-dd-HH:mm` |
| Daily limit | `0` is unlimited; counts resource releases per server-local day, not heartbeats |
| `license.dat` | Must be at the host classpath root |
| `SKYLICENSE_LICENSE_FILE_SECRET_FILE` | Customer-specific key; use the same value to generate and read `license.dat` |
| `basic-installation.id` | Persistent random identity in the client data directory; retain it to retain the binding |

Every customer needs an independent license-file secret. Copying an installation directory can copy its identity.
Basic does not provide hardware anti-cloning, native signature attestation or anti-debugging. Its software-version Build ID is
`7f10d350d700568181fc244d4f3b779c75ab57316ae8e0e573a1802b815c33f0`, security epoch `1`.

Bindings and quota are committed when resources are released. Entry/ACK failure can consume quota;
`DELIVERY_UNCONFIRMED` and unbinding do not refund delivered resources. Disabling a user/program or banning a license revokes online leases.

## Remote deployment and runtime configuration

Setup generates runtime files; the repository contains no real configuration, database, license, certificate or private key.
For manual deployment, start with [`deployment/config.example.json`](deployment/config.example.json) and [DEPLOYMENT.md](DEPLOYMENT.md).

Replace localhost TLS files with a certificate/key for the actual server domain, update `authTlsServerName`, and connect clients using that domain.
Keep the deployment directory, resources, database, private key and credential files owner-only.
Leave `allowedWebOrigins` empty for the embedded same-origin console.

The server requires independent, fixed audit/MFA keys through `SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE` and
`SKYLICENSE_MFA_ENCRYPTION_KEY_FILE`; each contains a nonzero 32-byte hexadecimal key. Bootstrap is first-start only.
Save the original audit/MFA keys separately for disaster recovery; do not regenerate them at every restart.

Basic uses the JVM CA store by default. For a private CA, set `SKYLICENSE_BASIC_CA_CERT_FILE` to its PEM file.
Optionally set `SKYLICENSE_BASIC_CERT_SHA256` to the SHA-256 of the TLS leaf certificate's DER encoding.
The packaged script selects the local test certificate; adjust it or launch directly for a public-CA server.
Run the following from the customer directory containing `license.dat` and `SkyLicense-basic.jar`:

```powershell
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = 'C:\MyCustomer\secrets\license-file-secret.txt'
Remove-Item Env:\SKYLICENSE_BASIC_CA_CERT_FILE -ErrorAction SilentlyContinue
java -cp '.;SkyLicense-basic.jar' cn.sky.license.BasicLauncher license.example.com:13331 MyApp 1.0.0
```

Run `java -jar SkyLicense-Server.jar --validate-config` from the deployment directory using the service account/environment before starting.
Missing/invalid config, unsafe permissions or invalid TLS fail closed. `web_magiclicense.db` is intentionally retained as a compatible database filename.

## Operations and backups

- `/health/live` and `/health/ready` return minimal `UP`/`DOWN` JSON; readiness failures return 503. Keep certificate/hostname verification enabled.
- Use authentication logs for rejection reasons and the operations page for audit-chain verification. Application logs use UTC under `runtime/logs/`.
- HTTP 401 means log in again. For 403, check MFA, role, Origin and CSRF. For program mismatch, check name/version/ownership;
  for `NOT_ADDRESS`, check bindings; for connection failures, check CA, hostname, Pin, ports, firewall and clocks.
- Stop the service before an offline backup. Supply the original audit/MFA keys and the independent `SKYLICENSE_BACKUP_HMAC_KEY_FILE`, then run:

```text
java -jar ../SkyLicense-Server.jar --create-backup <private-backup-directory>/backup.skybackup
java -jar ../SkyLicense-Server.jar --verify-backup <backup-path>/backup.skybackup
java -jar ../SkyLicense-Server.jar --extract-backup <backup-path>/backup.skybackup <new-restore-directory>
```

Replace angle-bracket paths. Keep backups outside the deployment and extract into a new destination.
Archives exclude TLS private keys and environment secrets: restore those separately, repair permissions and pass preflight before starting.
Preserve existing `runtime/`/`customer/` directories, databases and keys during upgrades; update only application files/scripts.

## Source layout and console development

```text
src/main/java/       Server, TLS/v4, license policy, audit and Web API
src/main/resources/  Application resources and bundled console assets
Client-Side/        Basic SDK, optional native bridge and release verifiers
web/                Vue source and npm lockfile
native/             Current SkyLicense-Client Rust JNI implementation (TLS/v4)
Cargo.toml          Rust workspace; Cargo.lock pins its dependencies
examples/basic-app/ Protected example source and settings.yml
deployment/         Setup tools, service templates and non-secret config example
tools/              Isolated integration tests
```

Bundled console assets make normal server builds usable without Node.js. To modify the UI, use
Node.js `^20.19.0 || >=22.12.0` and npm 10+:

```sh
cd web
npm ci --ignore-scripts
npm run build
```

Mirror `web/dist/` exactly into `src/main/resources/static/`, removing obsolete hashed assets, and rebuild the server.
The [Web README](web/README.md) includes safe Windows/Linux copy steps and an authenticated HTTPS development setup.
The default HTTP Vite development server is not a ready-to-use authenticated backend deployment.
Do not publish `node_modules/` or runtime environment files. The API defaults to same-origin `/api`.

Compatible dependency updates removed the known high-severity frontend findings. Five moderate development-tool advisories
remain; review `npm audit` before public deployment. Functional verification is not a full security certification.

## Tests and optional native SDK

The baseline passed **256 server tests and 25 SDK tests**, plus packaged-JAR authentication, entry/ACK, heartbeats,
rejection cases, online revocation, backup extraction and restart. Isolated tests need Python 3.10+ and `cryptography`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install cryptography
.\.venv\Scripts\python.exe tools/local-smoke-test.py --basic
.\.venv\Scripts\python.exe tools/test-basic-package.py
```

Linux (the packaged-script test is Windows-specific):

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install cryptography
python tools/local-smoke-test.py --basic
```

The package test exercises Windows PowerShell scripts. Tests create temporary directories and random credentials outside the checkout.
Builds and unit tests do not need runtime configuration.
For a fast private-directory/TLS/configuration check after `bootJar`, run `python tools/local-smoke-test.py --preflight-only`.

The native-enhanced SDK is optional and separate from Basic. `:Client-Side:jar` deliberately rejects missing, unsigned or non-hardened native assets.
The updated [SkyLicense-Client](native/README.md) under `native/` implements the current TLS/v4 protocol.
Historical client backups are not part of the active Rust workspace.
For a real **Strict** native system test, install Rust 1.97.1, JDK 17/21 and Python `cryptography`, build the Java classes/server
as above, and run from the repository root. Windows also needs MSVC Build Tools:

```sh
python tools/local-smoke-test.py --native --build-native
```

Use the virtual environment's Python; on Windows without activation this is .\.venv\Scripts\python.exe.

This builds and signs a CI-test native library, verifies binary hardening, and runs a real encrypted/transformed Java application.
It checks authentication, entry/ACK, verified heartbeats, repeat-auth rejection, license denial cases, untrusted TLS,
missing/tampered manifests, live revocation, host disable notification, audit integrity, backup and restore.
Credentials and certificates are generated only in a new private temporary directory; the server is stopped after the test.
The public CI identity and test certificate are **not production credentials**.

Customer integration is documented in the [native guide](native/README.md) and [deployment manual](DEPLOYMENT.md).
Protocol matching, regression coverage and remaining limits are recorded in [VALIDATION.md](VALIDATION.md).
Use `cn.sky.license.NativeLauncher` with both JVM hardening flags, or honor `disablePlugin()` in an embedded host and call
`SkyLicense.close()` at shutdown. Production requires your own TLS, signing identity and Windows Authenticode material.
The native release and SDK packaging workflows are both maintained here; release gates remain enabled.

The root Cargo workspace and Gradle project are independent. Building Basic does not require Rust or Node.js.
See [DEPLOYMENT.md](DEPLOYMENT.md), [API-DOC.md](API-DOC.md), and the [Linux](deployment/linux/README.md)/[Windows](deployment/windows/README.md) service guides.

License: see [LICENSE](LICENSE).
