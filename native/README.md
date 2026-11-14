[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense native client

This module contains the updated **SkyLicense-Client**, not the older protocol-v2 client.
It implements the current server's TLS 1.3 / protocol-v4 authentication, X25519/HKDF challenge,
AES-GCM resource and method delivery, loading ACK, signed heartbeats and monotonic lease revocation.
For the easiest Java-only setup, use the root [Basic edition guide](../README.md).

## Run a real local system test

Run all commands from the repository root. Install JDK 17/21, Python 3.10+ and the pinned Rust 1.97.1 toolchain.
On Windows, install Visual Studio MSVC C++ Build Tools and its Windows SDK, then add the target:

```powershell
rustup target add x86_64-pc-windows-msvc --toolchain 1.97.1
.\gradlew.bat test :Client-Side:test bootJar --no-daemon
python -m pip install cryptography
python tools/local-smoke-test.py --native --build-native
```

On Linux, use the native GNU Rust target and a C compiler/binutils:

```sh
./gradlew test :Client-Side:test bootJar --no-daemon
python3 -m pip install cryptography
python3 tools/local-smoke-test.py --native --build-native
```

The test builds a **Strict**, TLS-enabled native library; signs and verifies its CI-test integrity manifest;
checks PE/ELF hardening; deploys the real server; enrolls MFA; uploads the protected test program;
issues a real test license; and runs it through `SkyLicense`'s normal native extraction/loading path.
The protected program source is [SmokeEntry.java](../tools/fixtures/SmokeEntry.java); it includes inheritance,
an interface default method, a covariant return and an integer result. It is invoked again after key rotation.
Denial, malformed manifests, online revocation, Java host notification, audit, backup and restore are checked too.

Success ends with `web_smoke=PASS`. Logs, generated credentials and certificates remain in a new private temporary directory.
No existing deployment is touched, and the server is shut down after verification. The public CI identity is for tests only.
Use `--rust-toolchain <name>` or `--native-target <triple>` only when explicitly testing another installed compiler/target.

## Customer application

Publish a protected JAR and issue its license using the root guide, then generate `license.dat` with the same customer-specific
`SKYLICENSE_LICENSE_FILE_SECRET_FILE` used by the host. Keep `license.dat` at the host classpath root.
The included [DemoApp](../examples/basic-app/src/example/Entry.java) is compatible with either SDK.
With a properly signed `SkyLicense.jar`, start the standalone native host:

```powershell
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -cp ".;SkyLicense.jar" cn.sky.license.NativeLauncher license.example.com:13331 MyApp 1.0.0 customer-data
```

On Linux use `-cp '.:SkyLicense.jar'`. For a private CA, set `SKYLICENSE_NATIVE_CA_CERT_FILE` to its absolute PEM path.
Certificate chain, validity, hostname and compiled Strict certificate pins are all still verified; there is no trust-all switch.
For a public CA leave the variable unset. Both endpoints must allow the SDK's exact Build ID and security epoch.

Embedded hosts implement `PluginProxy`, call `new SkyLicense(proxy).authenticate(...)`, retain the client,
honor `disablePlugin()` by actually stopping protected operations, and call `close()` on shutdown.
`isSessionActive()` reports the native lease; `getHeartbeatCount()` counts authenticated PONGs only.
Only one native bridge is allowed per JVM. Repeated authentication after acceptance is refused before another resource release.
Expired/revoked protected dispatch throws `SecurityException`; the Java monitor also notifies the host.

## Production release

The root workspace owns `Cargo.toml` profiles, `Cargo.lock`, `.cargo/config.toml` and `rust-toolchain.toml`.
Use the root `release-native` and `package-sdk-release` workflows with protected environments.
They build Windows/Linux artifacts from this module and package verified assets from a release in this same repository.
Configure your own TLS certificate/pins, Ed25519 signing identity, Build ID/epoch and trusted Windows Authenticode material.
Never ship the test certificate, fixed CI seed or fixed CI Build ID to customers. Formal packaging checks are not disabled.

See [SECURITY.md](SECURITY.md) and [DEPLOYMENT.md](../DEPLOYMENT.md) for release identity and platform hardening requirements.
Original project attribution: Client of MagicLicense, by pi_ka.
