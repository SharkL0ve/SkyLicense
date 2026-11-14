[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense native client

This is the active **SkyLicense-Client** Rust JNI module in the unified repository.
Native release artifacts target x86-64 Windows and Linux.
It implements the current server's TLS 1.3 / protocol-v4 authentication, X25519/HKDF challenge,
AES-GCM resource and method delivery, loading ACK, signed heartbeats and monotonic lease revocation.
For the easiest Java-only setup, use the root [Basic edition guide](../README.md).

## Which workflow do I need?

- To verify the source locally: run the isolated system test below. It generates its own test identity/configuration.
- To integrate Java: follow the [Java SDK README](../Client-Side/README.md); applications do not call this Rust library directly.
- To deliver native SDKs to customers: complete the protected production release below. A local CI test DLL/SO is not a formal release.

Use the current server from this same repository. The native endpoint is a TLS/v4 TCP listener (`host:authPort`), not the HTTPS Web API.
Both Windows and Linux native runtime workflows have passed real system tests; see [validation](../VALIDATION.md).

## Run a real local system test

Run all commands from the repository root. Install JDK 17/21, Python 3.10+ and the pinned Rust 1.97.1 toolchain.
On Windows, install Visual Studio MSVC C++ Build Tools and its Windows SDK, then add the target:

```powershell
rustup target add x86_64-pc-windows-msvc --toolchain 1.97.1
.\gradlew.bat test :Client-Side:test bootJar --no-daemon
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install cryptography
.\.venv\Scripts\python.exe tools/local-smoke-test.py --native --build-native
```

On Linux, use the native GNU Rust target and a C compiler/binutils:

```sh
./gradlew test :Client-Side:test bootJar --no-daemon
python3 -m venv .venv
. .venv/bin/activate
python -m pip install cryptography
python tools/local-smoke-test.py --native --build-native
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
Build `bootJar`, then use `python tools/local-smoke-test.py --preflight-only` for a quick deployment check without the long native build.
Use the virtual environment's interpreter for all Python commands; Windows examples above do not require activation-policy changes.
The full test also needs `Client-Side:classes`, produced by the Java build above. Do not run source tests against a customer's live database.

The root workspace owns the toolchain, lockfile, build profiles and platform flags; run Cargo from the repository root, not from an
unrelated copy of the old client. `cargo fmt --all --check` needs no release secrets. `cargo clippy` and `cargo test` compile build identity
checks and require the same identity variables as their CI jobs; use [native-security-ci.yml](../.github/workflows/native-security-ci.yml)
as the test-environment reference, never as a source of production signing credentials.

## Customer application

Publish a protected JAR and issue its license using the root guide, then generate `license.dat` with the same customer-specific
`SKYLICENSE_LICENSE_FILE_SECRET_FILE` used by the host. Keep `license.dat` at the host classpath root.
The included [DemoApp](../examples/basic-app/src/example/Entry.java) is compatible with either SDK.
With a properly signed `SkyLicense.jar`, start the standalone native host:

Run from a customer directory containing that JAR and license.dat; set SKYLICENSE_LICENSE_FILE_SECRET_FILE to the customer's
absolute private credential file first. Host dependencies/unprotected resources must also be on the classpath.

```powershell
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -cp ".;SkyLicense.jar" cn.sky.license.NativeLauncher license.example.com:13331 MyApp 1.0.0 customer-data
```

On Linux use `-cp '.:SkyLicense.jar'`. For a private CA, set `SKYLICENSE_NATIVE_CA_CERT_FILE` to its absolute PEM path.
Certificate chain, validity, hostname and compiled Strict certificate pins are all still verified; there is no trust-all switch.
For a public CA leave the variable unset. The server must allow the SDK's exact Build ID and security epoch.
When switching from Basic to native, issue a fresh license or unbind the old Basic installation first: their identity algorithms differ.

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

1. In GitHub configure the `native-production` protected environment with the variables/secrets below and required reviewers.
2. Run [release-native](../.github/workflows/release-native.yml) with a new release tag, fresh Build ID, current epoch and minimum epoch.
   Windows uses native MSVC and signs Authenticode before the integrity manifest; Linux finalizes/strips before signing its manifest.
3. Verify the release contains SkyLicense_64.dll, libSkyLicense_64.so, their two .integrity files, SHA256SUMS and native-release.json.
4. Configure `production-sdk` with the same public key and Windows signing-certificate fingerprint, then run
   [package-sdk-release](../.github/workflows/package-sdk-release.yml) using that native tag and identical identity inputs.
5. Obtain SkyLicense.jar and its checksums/provenance from the formal SDK release. Add its Build ID to the server allowlist before delivery.

| Setting | Protected environment / meaning |
| --- | --- |
| SKYLICENSE_MANIFEST_PUBLIC_KEY | Both environments; raw Ed25519 public key, 64 hex characters |
| SKYLICENSE_MANIFEST_PRIVATE_KEY | native-production Secret only; independent private signing seed, never distributed |
| SKYLICENSE_CERT_SHA256 | native-production variable; actual TLS leaf DER SHA-256 |
| SKYLICENSE_CERT_SHA256_NEXT | Optional next certificate pin; requires a distinct primary pin |
| WINDOWS_CODESIGN_CERT_SHA256 | Both environments; Authenticode certificate DER SHA-256, not TLS pin or SHA-1 thumbprint |
| WINDOWS_CODESIGN_PFX_BASE64 / WINDOWS_CODESIGN_PASSWORD | native-production Secrets |
| WINDOWS_CODESIGN_TIMESTAMP_URL | native-production variable; trusted timestamp service |

Build ID and epochs are workflow inputs. Production keys/test identities are not interchangeable, and existing release tags are not
overwritten. See workflow files for the exact current gate and asset names; ordinary pushes do not publish a production SDK.

For certificate rotation, release an SDK with current + next pins first, update customers, switch the server certificate, then release
a cleanup SDK with the new primary pin only. Private-CA trust must also be provisioned where applicable.

## Runtime limits and troubleshooting

Strict is the default immutable compile-time profile; Balanced/Compatible are explicit alternatives described in [SECURITY.md](SECURITY.md).
Do not relax profiles, signature checks or TLS to fix a deployment error. Missing JVM flags, a wrong manifest, a stale pin, an unapproved
Build ID or a non-private data directory must be corrected at its source. Native anti-inspection is not protection against an administrator/root
who controls the machine, and the machine fingerprint is not hardware attestation.
The host must keep the lease alive and actually stop protected work on disablePlugin; see [SDK troubleshooting](../Client-Side/README.md#troubleshooting).

See [SECURITY.md](SECURITY.md) and [DEPLOYMENT.md](../DEPLOYMENT.md) for release identity and platform hardening requirements.
Original project attribution: Client of MagicLicense, by pi_ka.
