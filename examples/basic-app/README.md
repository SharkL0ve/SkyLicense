[English](README.md) | [简体中文](README.zh-CN.md)

# Protected DemoApp

## Build, publish and run

Run from the repository root:

```powershell
.\gradlew.bat basicExampleJar --no-daemon
```

Linux uses `./gradlew`. Output: `build/basic-example/DemoApp-1.0.0.jar`.
`basicReleaseZip` also includes this JAR, the server, SDK and runnable setup scripts.

1. Start the [server and Web console](../../README.md), log in and complete administrator MFA.
2. Create a program named exactly `DemoApp` and upload this JAR as version `1.0.0`.
3. Issue a license for the program and generate the customer's `license.dat` with its independent secret.
4. Run BasicLauncher or NativeLauncher as shown in the [SDK guide](../../Client-Side/README.md).
5. Expect `Protected DemoApp started successfully.`, then the launcher's accepted/heartbeat message and server log result `OK`.
6. Ban the license to check host shutdown; unban it and use a new process for another test.

The example works with both SDKs. Its application entry returns promptly; the host launcher, not the example entry, keeps the lease alive.
The separate [system-test fixture](../../tools/fixtures/SmokeEntry.java) additionally exercises inheritance, default methods,
covariant returns, exceptions and protected dispatch after key rotation.

## Create your own protected JAR

At its root include exactly one settings.yml (the example is [here](settings.yml)):

```yaml
Name: MyApp
Version: 1.0.0
EntryClass: example.Entry
EntryPoint: start
InfPort: false
KeepClasses: []
```

- Name/version must exactly match Web metadata and client arguments. Use 1–64 safe ASCII characters: a letter/digit first,
  followed by letters, digits, `.`, `_`, `+`, `-`. Program names cannot change after a version is uploaded.
- The JAR is at most 64 MiB. EntryClass must exist inside it with a public static no-argument entry, e.g. `public static void start()`.
- Initialize and return within the 30-second delivery ACK window. Start ongoing work in properly managed host/application services.
- Ordinary files such as images/configuration and external dependency JARs are not delivered by this class protocol;
  provide them on the customer host classpath/data path. Do not duplicate protected entry classes in that host.
- KeepClasses uses RE2/J patterns over slash-separated JVM class names. Matching classes retain transport encryption but skip
  method rewriting; use this selectively for reflection/serialization frameworks. InfPort is a legacy field; keep it false.
- Publish through Web/API, not by copying files into server resources/.

This example demonstrates execution, not a complete business service. Real hosts must implement disablePlugin and close the SDK on shutdown.
