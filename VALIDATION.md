# Protocol compatibility and validation

Validation date: 2026-11-14. The active `native/` module is the updated SkyLicense-Client.
The former native source was backed up outside the repository as `F:\Code\Source\MagicLicense-Client`.

## Compatibility conclusion

The current native client and server use the same protocol-v4 message formats and cryptographic domains.
An actual Windows MSVC Strict library, signed with the public CI test identity, completed TLS authentication,
loaded and executed transformed Java code, confirmed delivery, renewed signed heartbeats and handled live revocation.
This was a real server/SQLite/API/MFA deployment, not a mock, plaintext proxy or trust-all TLS verifier.

## Matched protocol boundaries

- ClientHello: protocol 4, raw X25519 public key, 32-byte nonce, security epoch, 32-byte Build ID,
  UTF-16 machine identity and program/license/bridge metadata; reserved fields are zero.
- Challenge: server public key/nonce/challenge/session ID; HKDF-SHA256 session derivation; timestamped
  `SkyLicense v4 challenge\0` HMAC binds the session, epoch and Build ID.
- Resource: separate transport/method keys bind session ID, epoch, Build ID and length-prefixed program/version.
  `SKYRES04` uses AES-256-GCM with resource AAD; `SKYCLS04` carries bounded compressed classes, entry and method metadata.
  `SKYMTH04` and `SKYSTR04` are separately authenticated lookup/string domains.
- Delivery: `SKDA` binds timestamp, session and success under a session-key HMAC. The server confirms with one byte;
  the authentication audit reaches `OK` only after successful entry and ACK.
- Lease: `SKHB` requests and responses are HMAC authenticated; replay/staleness and the 90-second monotonic lease are enforced.
  Only a verified PONG increments the exposed heartbeat counter.
- Artifact trust: Strict/Balanced require the Ed25519 `SKYINT02` sidecar, artifact SHA-256, target, Build ID and epoch.
  Strict also requires compiled certificate pins and JVM Attach hardening. Identity metadata is not hardware-backed remote attestation.

## Fixes found during integration

1. Added explicit private-CA PEM support without weakening WebPKI hostname/validity checks or compiled pins.
2. Added native lease status, verified heartbeat telemetry, Java host revocation notification, deterministic shutdown
   and a standalone `NativeLauncher`; one native bridge per JVM prevents replacing an active static dispatch bridge.
3. Revoked protected calls now throw `SecurityException`, rather than returning a normal string to business code.
   Ordinary Java business exceptions also propagate instead of being silently replaced with null.
4. Fixed server mutation of interfaces/annotations: private static dummy fields were invalid JVM bytecode.
   Added interface/default-method, annotation and ordinary-class loading regression tests; dummy names cannot collide.
5. Adapted workspace configuration and release/security workflows to this single repository.
6. Updated compatible frontend dependencies and rebuilt the bundled console; high-severity npm findings were removed.
7. Updated native TLS/async dependencies: rustls 0.23.46, rustls-webpki 0.103.17, webpki-roots 1.0.12 and Tokio 1.54.1.
   Private-CA parsing uses the maintained rustls-pki-types PEM API. Relevant upstream advisories include
   [TLS session debug redaction](https://rustsec.org/advisories/RUSTSEC-2026-0346),
   [distrusted intermediates](https://rustsec.org/advisories/RUSTSEC-2026-0382) and
   [trust-store update](https://rustsec.org/advisories/RUSTSEC-2026-0381).
8. Quoted hexadecimal CI identities to prevent YAML numeric conversion. Made the early oversized-request regression
   negotiate `Expect: 100-continue`, avoiding a Java 17/Linux upload-reset race without relaxing server limits.
9. Canonicalized Windows 8.3 aliases for backup secret exclusions, destination containment and resource catalogs;
   symbolic links/reparse points remain rejected. Linux-specific hardware-identity code passes warnings-denied Clippy.

## Verified locally

- JDK 21: 256 server tests and 25 Java SDK tests; zero failures/errors.
- Rust 1.97.1: formatting/Clippy with warnings denied and 66 unit tests.
- Rust 1.97.1 MSVC: Strict TLS system test, PE CFG/ASLR/DEP, signed manifest verification and normal Java native loading.
- Protected Java fixture: inheritance, interface default method, covariant return, integer result and dispatch after key rotation.
- Correct license succeeds; banned, expired and quota-exceeded licenses and an untrusted TLS certificate are rejected.
- Repeated authentication does not consume another resource release; final successful authentication audit is `OK`.
- A real JVM rejects missing/tampered manifests; live ban disables the host and blocks protected calls.
- Audit integrity, graceful shutdown, offline backup verification/extraction, restored startup and persistent sessions.
- The actual Basic ZIP's setup/server/license/client scripts, protected DemoApp, ACK and revocation.
- Frontend type check/production build; `npm audit --audit-level=high` succeeds. Five moderate development-tool advisories remain.

Linux native runtime validation is executed by `native-system-ci` on Ubuntu; do not treat cross-compilation alone as a runtime pass.
The `native-security-ci` matrix preserves profile, signature, hardening and load-negative checks on Windows and Ubuntu.

## Reproduce

```sh
./gradlew test :Client-Side:test bootJar basicReleaseZip --no-daemon
python -m pip install cryptography
python tools/local-smoke-test.py --native --build-native
python tools/local-smoke-test.py --basic
```

Windows uses `gradlew.bat`, MSVC C++ Build Tools and the `x86_64-pc-windows-msvc` Rust target.
See [native usage](native/README.md) / [中文指南](native/README.zh-CN.md). Credentials and TLS keys stay in private temporary
directories, never in Git. Public CI signing identities, test certificates and a passing functional suite are not a production security certification.
Production delivery still requires the operator's own TLS, release identity and trusted Windows Authenticode material.
