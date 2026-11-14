[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense Web console

## Use the console

The normal installation does not require a separate frontend server: `SkyLicense-Server.jar` serves this console and `/api`
from one HTTPS origin. Follow the [root quickstart](../README.md), then open `https://localhost:18443/` for the generated local setup.
There is no registration page or default password. The first account is `admin` with your bootstrap password.

1. Change the initial password through the account menu and log in again.
2. Open Account Security (`账户安全`), enroll an authenticator with the current password, confirm TOTP and save the once-only recovery codes.
3. Log in again. An administrator without MFA is intentionally limited to account-security operations.
4. Create a normal user if needed, choose the final program name, upload its matching JAR/version, and issue a license.
5. Generate the customer's license.dat and run the [Java SDK](../Client-Side/README.md); the console itself does not run protected customer code.
6. Confirm an authentication result of `OK`, test ban/unban/unbind, and verify operation-audit integrity.

| Page | Purpose |
| --- | --- |
| `/security` | TOTP, recovery codes and account security |
| `/programs` | Owned programs, versions and license issuance |
| `/licenses/:code` | License policy, bindings and history |
| `/bans`, `/auth-logs` | Scoped bans and authentication history |
| `/admin/users`, `/admin/programs`, `/admin/licenses` | Administrator account and cross-user management |
| `/admin/operations` | Sanitized operation audit and integrity verification |

Program ownership/roles are enforced by the backend, not only hidden menus. Keep a second verified MFA administrator;
one administrator can reset another's MFA after reauthentication, but cannot reset their own MFA this way.

## Build and embed

Use Node.js `^20.19.0 || >=22.12.0` and npm 10+ (package manager pin: npm 10.9.2).
From `web/`:

```sh
npm ci --ignore-scripts
npm run typecheck
npm run build
npm audit --audit-level=high
```

`npm run build` already includes type checking. The output is `web/dist/`; npm is the only package manager, and `.npmrc` disables
dependency lifecycle scripts. Do not add a second lockfile. Five moderate development-tool advisories were recorded during the
last validation; rerun the audit instead of treating that historical count as a permanent guarantee.

Mirror the build into `src/main/resources/static/` from the repository root, then rebuild the server.
These commands delete stale generated assets in that target; verify the two paths and do not point them at runtime data.

```powershell
# Windows, from repository root:
$root = (Resolve-Path .).Path
if (-not (Test-Path .\settings.gradle) -or -not (Test-Path .\web\dist\index.html)) { throw 'Wrong root or missing frontend build' }
$source = Join-Path $root 'web\dist'
$target = Join-Path $root 'src\main\resources\static'
robocopy $source $target /MIR /R:1 /W:1
if ($LASTEXITCODE -ge 8) { throw 'Static asset synchronization failed' }
.\gradlew.bat bootJar --no-daemon
```

```sh
# Linux, from repository root; rsync must be installed:
(
  set -eu
  test -f settings.gradle && test -f web/dist/index.html
  rsync -a --delete web/dist/ src/main/resources/static/
  ./gradlew bootJar --no-daemon
)
```

A Vite build alone does not update the server JAR. Deploy the rebuilt JAR and restart the server, then hard-refresh the browser.
The bundled server handles SPA routes. A separate static host must serve index.html for frontend history routes, but never replace API
errors or missing JavaScript assets with index.html.

## HTTPS development with the real backend

The checked-in `npm run dev` configuration listens on HTTP port 3000 and proxies `/api` to `https://localhost:8080`
with upstream certificate verification disabled. This is a development default, not the package's port 18443 and not a production setup.
Do not assume it is ready for secure session login. Use the following local override instead; it keeps upstream TLS verification on.

1. Initialize/start the local [Basic package](../deployment/basic/README.md), or provision a separate development server.
2. Add exactly `https://localhost:3000` to that server's config.json `allowedWebOrigins`, keeping the other required fields; restart it.
   This is a separate development Origin. Keep production's bundled-console configuration at `[]`.
3. Create `web/vite.local.config.ts` (ignored by Git) with the following content. Do not copy private keys into `web/public/`, dist or source control.

```ts
import { readFileSync } from 'node:fs'
import { Agent } from 'node:https'
import { mergeConfig } from 'vite'
import base from './vite.config'

function required(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`Missing ${name}`)
  return value
}

export default mergeConfig(base, {
  server: {
    host: 'localhost', port: 3000, strictPort: true,
    https: {
      key: readFileSync(required('SKYLICENSE_WEB_DEV_KEY_FILE')),
      cert: readFileSync(required('SKYLICENSE_WEB_DEV_CERT_FILE')),
      minVersion: 'TLSv1.3',
    },
    proxy: {
      '/api': {
        target: process.env.SKYLICENSE_WEB_DEV_API_ORIGIN || 'https://localhost:18443',
        changeOrigin: true, secure: true,
        agent: new Agent({
          ca: readFileSync(required('SKYLICENSE_WEB_DEV_CA_FILE')),
          minVersion: 'TLSv1.3',
        }),
      },
    },
  },
})
```

4. In a development-only terminal, set the paths to the generated localhost key/certificate and backend CA. Example from `web/`:

```powershell
$env:SKYLICENSE_WEB_DEV_KEY_FILE = 'C:\SkyLicenseLocal\SkyLicense-Basic\runtime\certs\auth-key.pem'
$env:SKYLICENSE_WEB_DEV_CERT_FILE = 'C:\SkyLicenseLocal\SkyLicense-Basic\runtime\certs\auth-chain.pem'
$env:SKYLICENSE_WEB_DEV_CA_FILE = $env:SKYLICENSE_WEB_DEV_CERT_FILE
$env:SKYLICENSE_WEB_DEV_API_ORIGIN = 'https://localhost:18443'
npm run dev -- --config vite.local.config.ts
```

Linux uses `export NAME='/absolute/path'` with the same names. Use a development certificate only, never a production private key.
Open `https://localhost:3000`, trust only your own development certificate, then log in/enroll MFA normally. Leave VITE_API_BASE_URL unset
so requests use `/api` through the proxy. Changing these server-only variables does not expose their contents to browser code.
`npm run preview` is not a preconfigured authenticated production server either.

## Separate frontend deployment and session contract

Prefer the embedded same-origin console or an HTTPS same-origin reverse proxy. If using a separate API origin, set public build-time
`VITE_API_BASE_URL=https://api.example.com/api` before `npm run build`, and add the exact frontend HTTPS Origin to `allowedWebOrigins`.
Changing `.env` after a build does not alter already-generated JavaScript. Never put secrets in `VITE_*` variables.

The API uses a Secure, HttpOnly `__Host-skylicense_session` cookie, not a bearer token in localStorage.
Axios sends credentials; the CSRF token stays in memory, is refreshed through `/api/auth/session`, and is sent as `X-CSRF-Token`
on writes. Do not disable Origin/CSRF checks to make deployment work. Separate-site cookies can be blocked by browser privacy policy;
same-origin deployment avoids this problem. A static host needs its own security headers/CSP; the API's CSP does not protect another site.
When proxying, preserve Origin, CSRF and Set-Cookie; allow the actual external Origin if the backend sees a different host/port.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Login returns 403 | Correct HTTPS Origin allowlist and proxy target; administrator MFA restriction |
| Repeated login / cookie absent | HTTPS, host consistency, Secure cookie and browser third-party cookie policy |
| 401 after password/MFA change | Reauthentication is expected; old sessions were revoked |
| API error says unrecognized format | VITE_API_BASE_URL must include /api; proxy must not return index.html for API routes |
| Upload rejected | 64 MiB limit, matching name/version, valid settings.yml and public static entry |
| Old UI after deployment | Synchronize dist exactly, rebuild/deploy JAR, restart, refresh browser cache |
| Direct route refresh is 404 | SPA history fallback on your separate static host |
| Proxy certificate error | Correct backend hostname/SAN, CA PEM, certificate validity and port; do not turn secure off |

See [server setup](../src/README.md), [API reference](../API-DOC.md) and [validation report](../VALIDATION.md).
