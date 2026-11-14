# SkyLicense native-client security

## Trust boundary

The native client raises the cost of runtime inspection; it cannot make a
machine controlled by an administrator or root user trustworthy. License
validity, session revocation, freshness, and resource release are therefore
server decisions. A terminal client event destroys local dispatch keys and
prevents later JNI calls from restoring the session.

## Security profiles

- `Compatible`: records missing JVM hardening flags and treats runtime Agent
  evidence as suspected; intended only for explicit development/profiler builds.
- `Balanced`: rejects an observed debugger/Agent, rotates in-memory
  keys every 30–90 seconds, and records missing launch hardening as evidence.
- `Strict` (default): also refuses initialization unless required JVM Attach
  hardening is present and uses shorter monitoring/rotation intervals.

The profile is immutable and selected at compile time. Exactly one profile is
required; ordinary builds select `security-strict` through Cargo's default
features. Development builds must opt out explicitly:

```text
cargo build --no-default-features --features security-compatible
cargo build --no-default-features --features security-balanced
```

Combining multiple profiles is a compile error. `insecure-plaintext` is accepted
only together with an explicit `security-compatible` build.

## Required JVM launch flags

Production launchers should use:

```text
-XX:+DisableAttachMechanism
-XX:-EnableDynamicAgentLoading
```

The second flag applies to JDK 9 and later. Strict mode rejects a launch that
does not provide the applicable flags. System properties set after JVM startup
are only a secondary hint and cannot replace these options.

## Windows protections

- Early and periodic debugger checks (`IsDebuggerPresent`, remote debugger,
  debug port/object/flags).
- Bounded inline-transfer checks on selected operating-system exports.
- Guard-page honeypots with a minimal vectored exception handler; cleanup and
  secret destruction never run inside the exception callback.
- Module-baseline Agent/Attach monitoring and process-owned JDWP listener
  checks.
- `VirtualLock` failures are retained as security evidence.

The JVM must not use process-wide dynamic-code prohibition because HotSpot JIT
requires executable code generation. External-handle detection remains off
until every candidate handle is duplicated and verified to target this PID.

## Linux protections

- `/proc/self/status` `TracerPid` checks at activation and periodically.
- `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlock`, and page-aligned
  `MADV_DONTDUMP` for key storage.
- Executable mapping/module baseline checks for known instrumentation agents.
- Managed `PROT_NONE` honeypot mappings with deterministic `munmap` cleanup.

The client intentionally does not treat `/proc/self/net/tcp` as process-owned;
that file describes the network namespace. It also does not install a strict
process-wide seccomp policy from inside the JVM.

## Hardware fingerprint

HWID collection does not execute utilities from `PATH`. Windows reads bounded
values through the registry API; Linux reads bounded machine, DMI, CPU, and
block-device identifiers from `/etc`, `/proc`, and `/sys`. Every component is
labelled and length-prefixed before hashing. If all sources are unavailable or
contain known placeholder values, authentication fails instead of returning a
shared empty fingerprint. This is a stable binding signal, not hardware-backed
attestation, and an administrator/root user can still spoof it.

## Auth and heartbeat protocol

Protocol v4 performs X25519 with an all-zero shared-secret check, derives the
session key with HKDF-SHA256, and requires a timestamped challenge HMAC before
the server releases resources. The challenge transcript binds the random
256-bit session ID, signed build ID, and client security epoch. Protocols v1-v3
are rejected at the server frame decoder with no legacy compatibility switch.

After challenge verification, independent transport and method-token keys are
derived from the session and length-prefixed plugin context. The resource
envelope, method lookup tokens, and protected string tokens use separate
AES-256-GCM magic/AAD domains. No fixed client/server padding password or
password-based derivation participates in protocol v4.

The authentication connection remains open after resource delivery. Only
after decryption, class definition, protection activation, heartbeat startup,
and successful entry-point return does the client send the fixed-length `SKDA`
frame. It binds the session id, timestamp, and success status under a
domain-separated session-key HMAC. The server confirms it with one byte before
the client may return `ACCEPT`. Failures before ciphertext release finalize the
audit as `DELIVERY_FAILED` and do not consume a binding or daily quota.
Disconnects, stale or invalid acknowledgements, entry-point failures, and the
30-second server timeout after release destroy the session and finalize the
audit as `DELIVERY_UNCONFIRMED`; the committed binding and daily quota are
retained. The client treats a missing confirmation as a terminal local
capability failure. `DELIVERY_ACK_ERROR` is therefore not retryable inside the
current JVM process; a fresh process must establish a new session after the
service is healthy.

The native bridge serializes authentication before network I/O and supports
one protected resource session per JVM. A concurrent attempt is rejected, and
a second attempt after successful initialization cannot consume another
server authorization. Once the resource length is received, every incomplete
initialization path is terminal locally because the server has already crossed
the binding/quota release boundary.

The build ID and security epoch identify a stock artifact whose sidecar was
signed by the release key. They are not hardware-backed remote attestation: a
machine administrator can copy public build metadata or modify a running
process. The server must therefore continue to enforce the license, build
allowlist, freshness, lease, and revocation decisions independently.
Heartbeat requests bind that ID, timestamp, environment hash, and HWID under
HMAC; heartbeat responses are also HMAC authenticated. Replayed or stale
timestamps are rejected and stale session keys are cleared. Both endpoints use
a monotonic 90-second lease: only a verified PONG renews the client lease, and
an expired server session cannot be resumed by a late heartbeat.

TCP framing is cumulative and length-bounded on the server. Resource parsing
has collection/string limits, exact bounded gzip expansion, and rejects
truncation, duplicate lookup keys, and trailing data.

## TLS deployment

Normal client builds and the authentication server require TLS 1.3. The server
loads a PEM certificate chain and private key from `authTlsCertificateChain`
and `authTlsPrivateKey` (defaults: `certs/auth-chain.pem` and
`certs/auth-key.pem`). If either file is absent, the authentication port stays
closed. An encrypted private key reads its password from
`SKYLICENSE_TLS_KEY_PASSWORD`.

For an explicitly managed private CA, set `SKYLICENSE_NATIVE_CA_CERT_FILE` to
an absolute PEM certificate path (regular file, at most 1 MiB). Its certificates
are added to the WebPKI trust store. Chain, validity, hostname and compiled
Strict pins are still checked. Invalid files fail closed; there is no trust-all
verifier or automatic plaintext fallback.

The certificate must contain the DNS name or IP address passed to the Java
client. Rust performs standard WebPKI chain and hostname verification. Strict
profile builds additionally require the leaf-certificate SHA-256 digest:

```powershell
$env:SKYLICENSE_CERT_SHA256 = "<64 lowercase or uppercase hex characters>"
$env:SKYLICENSE_CERT_SHA256_NEXT = "<optional next leaf-certificate SHA-256>"
cargo build --release --locked
```

Both pins are compiled into the native library and standard WebPKI/hostname
verification still runs before either pin is considered. The primary pin is
required by Strict builds; the optional next pin must be distinct and cannot
be configured without the primary pin.

Rotate certificates in three phases: ship a client containing the current pin
as `SKYLICENSE_CERT_SHA256` and the future pin as
`SKYLICENSE_CERT_SHA256_NEXT`, switch the server certificate after that client
is deployed, then ship a cleanup build with the future pin as the sole primary
pin. `insecure-plaintext` requires
`--no-default-features --features security-compatible,insecure-plaintext` and
is for isolated protocol tests only; never distribute such a build.

## Verification

Run locally:

```text
cargo fmt --all --check
cargo check --all-targets --locked
cargo test --locked -- --test-threads=1
```

The CI matrix executes these checks natively on current Windows and Ubuntu.
Passing a cross-compile alone is not considered Linux runtime verification.
`rust-toolchain.toml` and both release workflows pin Rust 1.97.1 so local,
CI, and production builds do not silently drift with the `stable` channel.

CI also runs RustSec against `Cargo.lock`, performs pull-request dependency
review, and uploads a CycloneDX JSON SBOM. Local supply-chain verification is:

```text
cargo audit
cargo cyclonedx --format json
```

## Signed native artifacts

Balanced and Strict builds require `SKYLICENSE_MANIFEST_PUBLIC_KEY` at compile
time and a `<library>.integrity` sidecar at load time. Manifest v2 signs the
product id, operating system, architecture, security epoch, 256-bit build id,
and library SHA-256. Generate and retain the private seed only in a protected
build secret store:

```powershell
$env:SKYLICENSE_MANIFEST_PRIVATE_KEY = (openssl rand -hex 32)
cargo run --locked --no-default-features --features security-compatible --bin sign_artifact -- --print-public-key
$env:SKYLICENSE_MANIFEST_PUBLIC_KEY = "<public_key from previous command>"
$env:SKYLICENSE_MIN_SECURITY_EPOCH = "1"
$env:SKYLICENSE_SECURITY_EPOCH = "1"
$env:SKYLICENSE_BUILD_ID = (openssl rand -hex 32)
$env:SKYLICENSE_ARTIFACT_CHANNEL = "production"
$env:SKYLICENSE_CERT_SHA256 = "<TLS leaf certificate SHA-256>"
$env:SKYLICENSE_CERT_SHA256_NEXT = "<optional next TLS leaf certificate SHA-256>"
cargo build --release --locked --lib --bin sign_artifact
# Apply Windows Authenticode signing or Linux strip operations before this step.
cargo run --release --locked --bin sign_artifact -- target/release/SkyLicense_64.dll
```

Release builds default to the `production` artifact channel and reject the
repository's fixed CI Build ID or CI manifest key. CI must opt in with
`SKYLICENSE_ARTIFACT_CHANNEL=ci-test`; never use that channel for customer
artifacts. `sign_artifact` repeats this gate when it runs. It rejects an all-zero
private seed, requires the private seed to derive the declared public key, and
requires the runtime public key, minimum/current epochs, and Build ID to match
the identity compiled into the signer. Rebuild the release tools with the
artifact identity; do not reuse a prebuilt signer by changing its environment.

Before copying native files into `Client-Side/src/main/resources`, run the
release verifier with the same public key, epoch, and Build ID used to compile
and sign the library:

```text
cargo build --release --locked --lib --bin sign_artifact --bin verify_artifact
cargo run --release --locked --bin verify_artifact -- target/release/SkyLicense_64.dll
```

`verify_artifact` is fail-closed: it requires
`SKYLICENSE_MANIFEST_PUBLIC_KEY`, `SKYLICENSE_MIN_SECURITY_EPOCH`,
`SKYLICENSE_SECURITY_EPOCH`, and `SKYLICENSE_BUILD_ID`, then checks the current
platform/architecture, manifest magic and reserved bytes, epoch, Build ID,
native-library SHA-256, and Ed25519 signature. The hardening scripts invoke the
same verifier when `--require-integrity-manifest` is requested. A structural
160-byte check alone is not a release check. The verifier also repeats the
artifact-channel gate and refuses runtime identity values that differ from
those compiled into the verifier.

For Linux, pass the final `.so` path instead. The signer inspects PE/ELF headers
and writes a 160-byte `.integrity` file. Any post-signing modification,
cross-platform sidecar, zero build id, security-epoch rollback, truncation,
wrong key, or missing sidecar causes `JNI_OnLoad` to return `JNI_ERR` before
secrets or monitor threads are initialized. Windows production releases should
use both Authenticode and this application manifest; sign with Authenticode
first so its PE modifications are included in the manifest hash.

Release hardening checks are reusable outside CI:

```powershell
$env:WINDOWS_CODESIGN_CERT_SHA256 = '<SHA-256 of the DER code-signing certificate>'
.\tools\verify-pe-hardening.ps1 -Path .\target\release\SkyLicense_64.dll `
  -RequireAuthenticode -RequireIntegrityManifest
```

```bash
bash ./tools/verify-elf-hardening.sh target/release/libSkyLicense_64.so \
  --require-integrity-manifest
```

## Automated native release

The `release-native` workflow is the only automated production path across the
native and server repositories. Configure a protected GitHub Environment named
`native-production` with required reviewers and these values:

```text
Variables:
SKYLICENSE_MANIFEST_PUBLIC_KEY
SKYLICENSE_CERT_SHA256
SKYLICENSE_CERT_SHA256_NEXT          # optional
WINDOWS_CODESIGN_CERT_SHA256
WINDOWS_CODESIGN_TIMESTAMP_URL

Secrets:
SKYLICENSE_MANIFEST_PRIVATE_KEY
WINDOWS_CODESIGN_PFX_BASE64
WINDOWS_CODESIGN_PASSWORD
```

Invoke the workflow with a new release tag, a fresh 256-bit Build ID, the
current security epoch, and the minimum accepted epoch. Its Windows job requires
the MSVC Rust host, requires CFG code generation, verifies that the PFX contains
the pinned code-signing certificate, applies Authenticode before the application
manifest, and re-verifies the actual DLL signer certificate. Its Linux job performs the
final strip before manifest creation and verifies ELF hardening plus a real JVM
load. The publish job runs only after both platforms succeed, refuses to replace
an existing tag, and emits exactly the four native files, `SHA256SUMS`, and
public release metadata. GitHub artifact attestations bind all six release files
to the workflow identity and source commit.

Enable GitHub immutable releases for the native repository. The server
repository's protected `package-sdk-release` workflow downloads those signed
release assets and independently verifies the release checksum set and public
metadata, the pinned Authenticode signer certificate, pure-Java PE/ELF parsing,
Ed25519 manifests, artifact hashes, release identity, and final JAR contents.
Configure the same `WINDOWS_CODESIGN_CERT_SHA256` protected variable in the
server repository's `production-sdk` environment. That workflow requires a new
SDK release tag, emits `MagicLicense.jar`, a JAR-only `SHA256SUMS`, public SDK
metadata, and build provenance, then creates a non-overwriting GitHub Release.
Temporary Actions artifacts and locally copied binaries are not an authorized
customer-delivery boundary.

## SDK packaging gate

The Java SDK packaging task requires all four x86-64 native artifacts and the
same release identity in both manifests. It validates PE32+/CFG/load-config and
ELF64/RELRO/BIND_NOW/NX/no-RWX properties without relying on host tools, then
validates the native SHA-256 and Ed25519 signature and checks that the final JAR
does not contain legacy native names. Set the release variables before packaging:

```text
SKYLICENSE_MANIFEST_PUBLIC_KEY=<release public key>
SKYLICENSE_MIN_SECURITY_EPOCH=<minimum epoch>
SKYLICENSE_SECURITY_EPOCH=<artifact epoch>
SKYLICENSE_BUILD_ID=<64 hexadecimal Build ID>
SKYLICENSE_ARTIFACT_CHANNEL=production
```

Then run `:Client-Side:verifyNativeReleaseArtifacts` and
`:Client-Side:jar`. The task prints `allowed_client_build_ids` so the exact
value can be copied into the server configuration. The repository CI test
identity is accepted only when `SKYLICENSE_ARTIFACT_CHANNEL=ci-test`; it must
never be used for a customer release.
