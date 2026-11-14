# SkyLicense Web Console

This is the `web/` module of the unified SkyLicense repository. The Java server is
in `../src/`, the Java SDK is in `../Client-Side/`, and the current Rust client is
in `../native/`. For setup and license verification, start with the root
[English guide](../README.md) or [Chinese guide](../README.zh-CN.md).

Run the following commands from this `web/` directory. The dashboard uses npm as its only package manager. Node.js must satisfy
`^20.19.0 || >=22.12.0`; CI currently pins Node.js 22.14.0 and npm 10.9.2.

```text
npm ci
npm run typecheck
npm run build
npm audit --audit-level=high
```

Lifecycle scripts are disabled through `.npmrc` to reduce dependency-install
risk. Do not add another package-manager lock file. After a production build,
mirror `dist/` exactly into the server repository's
`../src/main/resources/static/` directory so stale content-hashed assets are
removed. The standalone frontend CI has been relocated to the root
`.github/workflows/frontend-security-ci.yml`; its commands run under `web/`.
The dependency audit gate is retained: known high-severity findings were fixed; five moderate development-tool advisories remain.
