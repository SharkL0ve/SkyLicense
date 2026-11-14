[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense Java SDK

## Use a license end to end

1. Start the [server and console](../README.md#getting-started-the-working-basic-edition).
2. Upload your [protected JAR](../examples/basic-app/README.md), then issue a license for its exact name/version.
3. Provision a private customer directory and an independent license-file secret.
4. Generate `license.dat` interactively, then run one of the launchers below.
5. Check the server authentication log for `OK`; keep the host alive for heartbeats and test a live ban.

The SDK invokes the delivered entry itself. Do not bundle the protected entry in the host, and do not invoke it a second time.

## Choose and build an SDK

| | Basic | Native |
| --- | --- | --- |
| Customer JAR | `SkyLicense-basic.jar` | `SkyLicense.jar` |
| Client class | `cn.sky.license.BasicLicenseClient` | `cn.sky.license.SkyLicense` |
| Standalone host | `cn.sky.license.BasicLauncher` | `cn.sky.license.NativeLauncher` |
| Identity | Persistent random installation ID | Windows/Linux machine fingerprint |
| Native runtime protection | Not included | Compile-time profile; Strict by default |
| Target runtime | JDK 17/21, no DLL/SO dependency | JDK 17/21, x86-64 Windows/Linux plus signed assets |

Run from the repository root:

```powershell
.\gradlew.bat :Client-Side:test :Client-Side:basicJar --no-daemon
```

Linux uses `./gradlew`. Basic output: `Client-Side/build/libs/SkyLicense-basic.jar`.
The [full runnable package](../deployment/basic/README.md) also provides setup scripts and DemoApp.

Native `:Client-Side:jar` deliberately requires both signed/hardened platform libraries and their `.integrity` files;
failure without these assets is expected, not an instruction to disable the gate. Use the
[native guide](../native/README.md) and protected release workflows for formal packaging.
Do not put both SDK JARs on one classpath: they contain overlapping Java classes.

## Prepare the customer directory

Keep these files under the customer's runtime account, separate from server data:

```text
customer/
  SkyLicense-basic.jar            # OR SkyLicense.jar
  license.dat
  secrets/license-file-secret.txt
  ca-cert.pem                    # public certificate/CA, only if needed
  customer-data/                 # persistent SDK state; created on first use
```

Use an independent cryptographically random secret for every customer (recommend at least 32 random bytes).
For the local package, `SetupLocal.ps1` / `sh run.sh setup` creates one customer directory automatically.
From that extracted package, provision another with
`java -cp SkyLicense-basic.jar SetupLocal.java client customer-b`; it refuses an existing destination.
For manually provisioned deployments, use your credential manager and owner-only permissions. Never replace a live secret accidentally.

From the customer directory, select the same secret for generation and runtime:

```powershell
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = (Resolve-Path .\secrets\license-file-secret.txt).Path
java -cp .\SkyLicense-basic.jar cn.sky.license.LicenseFileTool .\license.dat
```

```sh
export SKYLICENSE_LICENSE_FILE_SECRET_FILE="$PWD/secrets/license-file-secret.txt"
java -cp ./SkyLicense-basic.jar cn.sky.license.LicenseFileTool ./license.dat
```

For native, replace the JAR name with `SkyLicense.jar`. Enter the code at the prompt, not as a command-line argument.
The file uses authenticated `SKYLIC03` format. It must be at the classpath root; `java -jar` does not automatically include `.`.
The secret's `_FILE` path must be absolute. Do not also set `SKYLICENSE_LICENSE_FILE_SECRET`.

## Launch a customer application

All commands below run from the customer directory. Endpoint format is `host:port`, without `https://` or a path.
Use the authentication port (`13331` in the examples), not the Web console port.
For a managed private CA, set the appropriate variable to the absolute PEM path; leave it unset for a public CA:

```powershell
# Basic, for the local setup certificate:
$env:SKYLICENSE_BASIC_CA_CERT_FILE = (Resolve-Path .\ca-cert.pem).Path
java -cp '.;SkyLicense-basic.jar' cn.sky.license.BasicLauncher localhost:13331 DemoApp 1.0.0 customer-data
```

```sh
export SKYLICENSE_BASIC_CA_CERT_FILE="$PWD/ca-cert.pem"
java -cp '.:SkyLicense-basic.jar' cn.sky.license.BasicLauncher localhost:13331 DemoApp 1.0.0 customer-data
```

Native, with a formally packaged SDK and the actual server/domain/allowed Build ID:

```powershell
# Only for a private CA:
$env:SKYLICENSE_NATIVE_CA_CERT_FILE = (Resolve-Path .\ca-cert.pem).Path
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -cp '.;SkyLicense.jar' cn.sky.license.NativeLauncher license.example.com:13331 MyApp 1.0.0 customer-data
```

```sh
export SKYLICENSE_NATIVE_CA_CERT_FILE="$PWD/ca-cert.pem" # private CA only
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -cp '.:SkyLicense.jar' cn.sky.license.NativeLauncher license.example.com:13331 MyApp 1.0.0 customer-data
```

Private-CA trust does not bypass certificate chain, validity, hostname or the native Strict compiled pins.
Basic can additionally use `SKYLICENSE_BASIC_CERT_SHA256` to pin the TLS leaf DER SHA-256.
Native pins are build-time settings, not runtime environment overrides; certificate changes may require a new SDK release.

Successful launch prints `License accepted; protected entry completed; ... heartbeat active.`
The launchers remain alive; authentication failure exits `2`, and live revocation exits `3`.
Basic heartbeats are about 20 seconds apart; native heartbeats about 30 seconds. Both use a 90-second lease.

## Embed in an existing Java host

Implement `PluginProxy`; the existing [BasicLauncher.java](src/main/java/cn/sky/license/BasicLauncher.java) and
[NativeLauncher.java](src/main/java/cn/sky/license/NativeLauncher.java) are complete, compilable host examples.

| Method | Host responsibility |
| --- | --- |
| `getDataFolder()` | Private, writable, persistent SDK data directory |
| `getResource(String)` | Read `license.dat` from the host classloader/resources |
| `getResourceType()` | `Resource.CLEAR_LOWERCASE` for the normal `license.dat` name |
| `isPrimaryThread()` | Report the host's primary thread correctly; authenticate on the appropriate thread |
| `info(String)` | Route SDK information to a log without appending credentials |
| `disablePlugin()` | Actually stop protected work; a standalone host can terminate its process |

Minimal lifecycle fragment, with a previously created `PluginProxy proxy`:

```java
import cn.sky.license.BasicLicenseClient;
import cn.sky.license.Response;

BasicLicenseClient client = new BasicLicenseClient(proxy);
Response result = client.authenticate("license.example.com:13331", "MyApp", "1.0.0");
if (result != Response.ACCEPT) {
    client.close();
    throw new IllegalStateException("License authentication failed: " + result);
}
Runtime.getRuntime().addShutdownHook(new Thread(client::close));
// Retain client for the host lifetime. SDK already ran the protected entry.
```

For native use `SkyLicense` in place of `BasicLicenseClient` and import `cn.sky.license.SkyLicense`.
Hold a strong reference, keep the host running, and call `close()` during shutdown. `isSessionActive()` reports the lease;
native `getHeartbeatCount()` counts authenticated PONGs only. One native bridge is allowed per JVM, even after close;
do not recreate clients to bypass terminal failures. Only one Basic session may be active at once.

Native calls after revocation throw `SecurityException`. Ordinary business exceptions propagate normally.
Merely logging/throwing from a background `disablePlugin()` callback does not stop the rest of an application;
cancel tasks, close services and prevent protected work from continuing.

## Customer delivery checklist

- Deliver only the host/SDK, customer-specific `license.dat` and secret, required public CA, and unprotected runtime dependencies/resources.
- Never deliver the server database, server TLS private key, audit/MFA/backup keys, or administrator credentials.
- Keep name/version identical in settings.yml, Web upload and client arguments; keep dependencies on the host classpath.
- Preserve `customer-data/basic-installation.id` for Basic binding. A copied data directory can copy this identity; it is not anti-cloning.
- When moving Basic → native, use a fresh license or explicitly unbind the old installation: their identity algorithms differ.
- For native, verify x86-64 JVM, release signature/manifest, compiled TLS pins, and the server Build ID/epoch allowlist.
- Test a successful `OK`, a wrong/expired/banned license, and a live ban before customer delivery.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `license.dat` missing / unreadable | Classpath includes customer root; correct `PluginProxy` resource implementation |
| License-file authentication failure | Generation/runtime use the same customer secret; file is SKYLIC03 |
| `SOCKET_ERROR_CONNECT` | Auth port, firewall, exact TLS hostname, CA/validity/pins, synchronized clocks |
| `CLIENT_BUILD_ERROR` | Allowed Build ID/epoch and correctly signed SDK artifacts |
| `HWID_ERROR` | Native machine identifiers available; supported Windows/Linux environment |
| `NOT_ADDRESS` | IP/HWID/Basic installation bindings and limits; unbind intentionally, do not delete state blindly |
| `DAILY_AUTH_LIMIT` | Resource-release quota, counted by server-local date; heartbeats do not consume it |
| `BLACKLIST` | License expiration/status and applicable ban rules |
| Entry errors / `DELIVERY_ACK_ERROR` | Correct entry/dependencies; return within 30 seconds; repair cause and restart JVM |
| `SESSION_ALREADY_INITIALIZED` / `SESSION_REVOKED` | Do not authenticate twice or reuse a terminal native process |
| Native load failure | Correct architecture, intact library/manifest, private writable data directory, both JVM flags |

Response details are normalized to stable constants. A `retry()` hint is not permission to retry after resource release:
when uncertain, fix the cause and restart the host. Released resources may consume quota even when entry/ACK fails.

Tests: `:Client-Side:test`, `python tools/local-smoke-test.py --basic`, and
`python tools/local-smoke-test.py --native --build-native` after Java build. See [validation](../VALIDATION.md).
