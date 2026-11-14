[English](README.md) | [简体中文](README.zh-CN.md)

# Linux deployment templates

For the first local demo use the [Basic package](../basic/README.md). This guide provisions a dedicated production service;
prepare the server build, real-domain TLS and persistent keys using the [server README](../../src/README.md).
Commands using these template filenames run from deployment/linux/ in the source checkout. Do not execute them against an existing
deployment without a verified backup and an upgrade plan.

These files assume the application is installed in `/opt/skylicense`, the
service account is `skylicense`, and JDK 17/21 is `/usr/bin/java`. The host's systemd must support the directives in the templates,
including LoadCredential; review units with systemd-analyze verify on the target host. Copy the unit
files into `/etc/systemd/system/` and the backup helper into
`/usr/local/libexec/skylicense-backup`, then make the helper executable.

Create the service account and owner-only directories before copying the live
deployment:

```bash
sudo useradd --system --home /opt/skylicense --shell /usr/sbin/nologin skylicense
sudo install -d -o skylicense -g skylicense -m 700 /opt/skylicense
sudo install -d -o skylicense -g skylicense -m 700 /opt/skylicense/certs /opt/skylicense/resources
sudo install -d -o root -g root -m 700 /etc/skylicense/credentials
sudo install -d -o skylicense -g skylicense -m 700 /var/backups/skylicense
sudo install -d -o root -g root -m 755 /usr/local/libexec
sudo install -o root -g root -m 755 skylicense-backup /usr/local/libexec/skylicense-backup
```

Write `operation-log-hmac`, `mfa-encryption-key`, and backup credential files
with `umask 077`, set their owner to `root`, and never put their contents in
the unit or repository. The MFA key is a fixed 32-byte hexadecimal value and
must be backed up separately from the SQLite database. `LoadCredential` exposes a
private runtime copy to the service and the application receives only the
absolute `_FILE` path. For an encrypted TLS key, add the optional credential
lines shown in the unit templates.

Stage SkyLicense-Server.jar and config.json under /opt/skylicense and the PEM files under its certs/.
Replace the example hostname/Build ID with the actual TLS name and accepted SDK identity.
Make these files owned by skylicense and mode 600; directories stay 700. Use absolute owner-only credential files through LoadCredential.
Audit, MFA and backup keys must be independent nonzero 64-hex values. First-start bootstrap password is 12–128 characters with at least
three character classes. Never overwrite existing keys during an upgrade.

Install the main service without starting it yet:

```bash
sudo install -m 644 skylicense.service /etc/systemd/system/skylicense.service
```

Before the FIRST start, provision /etc/skylicense/credentials/bootstrap-admin-password, then install the bootstrap drop-in:

```bash
sudo install -d -m 755 /etc/systemd/system/skylicense.service.d
sudo install -m 644 skylicense-bootstrap.conf.example /etc/systemd/system/skylicense.service.d/10-bootstrap.conf
sudo systemctl daemon-reload
sudo systemctl enable --now skylicense.service
sudo systemctl status skylicense.service
```

ExecStartPre runs --validate-config with the actual service identity and mapped credentials. Inspect failures with
sudo journalctl -u skylicense.service -n 100; do not bypass owner-only checks.
Open https://your-certificate-host:18443/ (or configured webPort), log in, change the password, enroll MFA and verify a second admin.
Remove 10-bootstrap.conf and its source credential, daemon-reload, then restart once to clear the bootstrap environment.
The service refuses a bootstrap variable after an administrator exists.
For encrypted PEM, put persistent TLS-key-password LoadCredential/Environment mappings in a separate drop-in, not the temporary
bootstrap file that will be removed. See the optional lines in the template.

Enable the scheduled backup only after a successful manual validation:

```bash
sudo install -m 644 skylicense-backup.service /etc/systemd/system/skylicense-backup.service
sudo install -m 644 skylicense-backup.timer /etc/systemd/system/skylicense-backup.timer
sudo systemctl daemon-reload
sudo systemctl start skylicense-backup.service
sudo systemctl enable --now skylicense-backup.timer
```

The backup unit stops the main service, creates and verifies an authenticated
archive outside the live directory, and starts the main service in
`ExecStopPost` only when it was active before the job. Monitor both the unit
result and the archive volume; configure
retention and encrypted off-host replication separately.
The timer is scheduled for 02:15 UTC with up to 15 minutes randomized delay, not local wall-clock 02:15.
The archive is authenticated but not encrypted. Restore into a new directory and separately restore TLS/private credentials;
preflight must pass before changing the service working directory. Do not run a second instance against the live database.

After startup, use `https://<configured-host>:<webPort>/health/live` for
liveness and `/health/ready` for readiness. The latter requires the native TLS
listener, SQLite, and healthy operation-audit persistence as well as the Web process. Monitoring must keep normal CA
and hostname validation enabled. Both endpoints are unauthenticated and return
only `UP`/`DOWN`; firewall the administration port to trusted operator,
load-balancer, and monitoring sources. Application logs are written to
`/opt/skylicense/logs/latest.log`, roll daily or at 50 MiB, and enforce bounded
age, file-count, and aggregate-size retention on rollover.
