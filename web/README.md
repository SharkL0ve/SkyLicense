# SkyLicense Web Console

The dashboard uses npm as its only package manager. Node.js must satisfy
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
removed.
