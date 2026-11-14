[English](QUICKSTART.md) | [简体中文](QUICKSTART.zh-CN.md)

# Complete first-use checklist

For commands and menu names in context, start with the [main README](README.md).
This checklist connects every component without mixing local test artifacts with production releases.

## 1. Choose Basic or native

Use Basic for the first working installation. It needs a full JDK 17/21, not Rust/Node.js.
Native uses the same TLS/v4 server and adds signed x86-64 Windows/Linux runtime protections;
formal delivery additionally needs production TLS/pins, an Ed25519 release identity and Windows Authenticode material.
Use the [native guide](native/README.md) for that release process, not a CI DLL/SO copied from a test.

## 2. Build and extract

From repository root:

```powershell
.\gradlew.bat :test :Client-Side:test basicReleaseZip --no-daemon
```

Linux uses ./gradlew. Extract build/distributions/SkyLicense-Basic-1.0.0.zip outside build/.
Do not initialize runtime data in the checkout. The package already contains the console.
Only when changing UI code, follow the [Web build/synchronization guide](web/README.md) first.

## 3. Initialize and start the server

From the extracted SkyLicense-Basic directory, use a normal user terminal:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\SetupLocal.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\StartServer.ps1
```

Linux: sh run.sh setup, then sh run.sh server. Setup prompts for your initial admin password and refuses existing runtime/customer
directories. Web is https://localhost:18443/; client verification is localhost:13331. The generated certificate is localhost-only, valid 30 days.
Normal later starts use server/client scripts directly, not setup again.

For production, use an independent [server runtime](src/README.md), actual-domain TLS, private files and fixed credentials;
install [systemd](deployment/linux/README.md) or [WinSW](deployment/windows/README.md) after preflight passes.

## 4. Set up Web accounts

Log in as admin with your setup password, change it, log in again, enroll TOTP under Account Security, save recovery codes, and log in again.
An admin without MFA cannot access business APIs. Create and verify a second MFA admin for recovery.
Remove the bootstrap mapping/source before the next start. See the [console guide](web/README.md).

## 5. Publish a protected application

Create DemoApp, upload DemoApp-1.0.0.jar as 1.0.0 and issue a license (initially one IP, one installation and unlimited daily quota).
For your own JAR see [the example guide](examples/basic-app/README.md). Name/version must agree everywhere;
the public static no-argument entry must return within 30 seconds. Upload through Web/API, not by copying into resources/.

## 6. Generate the license file and run

In another terminal, from the extracted package:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\MakeLicense.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\StartClient.ps1
```

Linux: sh run.sh license, then sh run.sh client. Enter the issued code interactively.
Expect the protected DemoApp message, an accepted/heartbeat message, and final server authentication log OK.
The customer license file and runtime must use the same independent customer secret. Do not distribute server secrets/data.
Native launch/classpath/CA/JVM flags and embedded-host lifecycle are in the [Java SDK guide](Client-Side/README.md).

## 7. Acceptance and operations

- Keep the client alive, ban its license and verify the host stops protected work; unban and use a new process to test again.
- Preserve client installation state; switching Basic to native requires a fresh license or explicit unbinding.
- Check HTTPS /health/live, /health/ready and operation-audit integrity with normal TLS verification.
- Stop gracefully before offline backup; restore into a new directory with original keys and pass preflight before switching.
- For remote customers replace localhost TLS, use the actual domain/authentication port and verify the SDK Build ID/epoch.
- Review [validation and limits](VALIDATION.md) and the [deployment index](deployment/README.md) before production.
