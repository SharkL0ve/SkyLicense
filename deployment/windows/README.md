[English](README.md) | [简体中文](README.zh-CN.md)

# Windows deployment templates

For the first local demo use the [Basic package](../basic/README.md) in a normal user terminal.
This guide configures an installed production service; first build the server and prepare real-domain TLS using the
[server README](../../src/README.md). The installer intentionally changes ownership/ACLs on the selected live and backup trees;
do not point it at the checkout or an unrelated directory.

The template assumes a dedicated gMSA (recommended) or dedicated local service
account, JDK 17/21, and a verified WinSW release. WinSW is intentionally not
bundled. Record its official release SHA-256 and pass it to the installer;
never download an unverified wrapper at install time.

Copy `SkyLicense.xml` into the deployment root and replace its Java path. Copy
the server JAR, config, certificates, and resources there as well. A brand-new
installation may omit `web_magiclicense.db`; the service account creates it on
first startup. Existing deployments and restores must retain the database and
any `web_magiclicense.db-wal`/`web_magiclicense.db-shm` sidecars.
Create `operation-log-hmac.txt`, `mfa-encryption-key.txt`, and, for offline backup,
`backup-hmac.txt` under the root `secrets` directory. The MFA file contains a
non-zero 64-character hexadecimal value. Each file contains one
value and may end with one newline. During first start, temporarily add the
bootstrap mapping shown in the XML, log in, change the password, then remove
the mapping and source file.
Complete administrator MFA, verify a second administrator, then restart to ensure bootstrap is no longer mapped.
Use separate independent nonzero 64-hex audit/MFA/backup keys. Do not regenerate them during upgrades.
The XML's Java path is an example: change it to the installed java.exe path before installation.
Prepare the account and its Log on as a service right; for a gMSA ensure this host is authorized to use it.

Run the installer from an elevated PowerShell prompt:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-SkyLicense.ps1 `
  -DeploymentRoot 'C:\ProgramData\SkyLicense' `
  -ServiceAccount 'CONTOSO\skylicense$' `
  -WinSWPath 'C:\staging\winsw-x64.exe' `
  -ExpectedWinSWSha256 '<64-hex-sha256-from-your-release-record>'
```

The installer prompts securely for a normal service account password; gMSA names ending in $ do not require a password.
It installs/configures the service but does not start it. Set the documented _FILE mappings and run --validate-config in the deployment
directory as that service account, then start the SkyLicense service through your approved service-management process.
Windows service wrappers do not inherit an interactive terminal's environment; persist mappings in SkyLicense.xml.

The script removes inherited ACLs and makes the service account the sole allow
principal on live and backup paths. The server preflight is the final authority;
run it as the service account and fix any owner/ACL report before starting.
Do not grant `Administrators`, `Users`, `SYSTEM`, or `Everyone` allow entries
to the deployment, database, resource, certificate, or secret paths. Use a
separate staging directory for upgrades because the service account owns the
live tree.

`Backup-SkyLicense.ps1` is an offline operation and writes outside the live
deployment. Schedule it under the same service account; the installer grants
that account only query/start/stop rights on the SkyLicense service. The script
stops the service, creates and verifies an authenticated archive, and starts
the service again only when it was running before. Store the backup root on an
encrypted volume and replicate verified archives off host.
Pass the actual Java path when different from the template:

```powershell
.\Backup-SkyLicense.ps1 -DeploymentRoot 'C:\ProgramData\SkyLicense' -BackupRoot 'C:\ProgramData\SkyLicenseBackups' -JavaPath 'C:\YourJdk\bin\java.exe'
```

The archive has authentication but no encryption. Recover into a new directory, restore the excluded TLS key and original credentials,
apply ownership/ACLs and pass preflight before switching the service. Never use forced termination as the normal upgrade procedure.

After startup, monitor `https://<configured-host>:<webPort>/health/live` for
process liveness and `/health/ready` for traffic readiness. Readiness requires
the native TLS listener, SQLite, and healthy operation-audit persistence in addition to the Web process. Configure
the monitoring client with normal CA and hostname validation; do not suppress
certificate errors. Both endpoints are unauthenticated and disclose only
`UP`/`DOWN`, so restrict the administration port to trusted monitoring and
operator networks. Application logs roll separately from WinSW wrapper logs:
`logs/latest.log` rolls daily or at 50 MiB and archives are bounded by age,
count, and aggregate size.
