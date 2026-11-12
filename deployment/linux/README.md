# Linux deployment templates

These files assume the application is installed in `/opt/skylicense`, the
service account is `skylicense`, and Java 17 is `/usr/bin/java`. Copy the unit
files into `/etc/systemd/system/` and the backup helper into
`/usr/local/libexec/skylicense-backup`, then make the helper executable.

Create the service account and owner-only directories before copying the live
deployment:

```bash
sudo useradd --system --home /opt/skylicense --shell /usr/sbin/nologin skylicense
sudo install -d -o skylicense -g skylicense -m 700 /opt/skylicense
sudo install -d -o root -g root -m 700 /etc/skylicense/credentials
sudo install -d -o skylicense -g skylicense -m 700 /var/backups/skylicense
sudo install -o root -g root -m 755 skylicense-backup /usr/local/libexec/skylicense-backup
```

Write `operation-log-hmac`, `mfa-encryption-key`, and backup credential files
with `umask 077`, set their owner to `root`, and never put their contents in
the unit or repository. The MFA key is a fixed 32-byte hexadecimal value and
must be backed up separately from the SQLite database. `LoadCredential` exposes a
private runtime copy to the service and the application receives only the
absolute `_FILE` path. For an encrypted TLS key, add the optional credential
lines shown in the unit templates.

Install and validate the main service:

```bash
sudo install -m 644 skylicense.service /etc/systemd/system/skylicense.service
sudo systemctl daemon-reload
sudo systemctl enable --now skylicense.service
sudo systemctl status skylicense.service
```

For the first start, install `skylicense-bootstrap.conf.example` as a drop-in,
create the bootstrap credential, run `systemctl restart skylicense`, log in,
change the password, then remove the drop-in and source credential before the
next restart. The service fails closed if the bootstrap variable remains after
an administrator exists.

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

After startup, use `https://<configured-host>:<webPort>/health/live` for
liveness and `/health/ready` for readiness. The latter requires the native TLS
listener, SQLite, and healthy operation-audit persistence as well as the Web process. Monitoring must keep normal CA
and hostname validation enabled. Both endpoints are unauthenticated and return
only `UP`/`DOWN`; firewall the administration port to trusted operator,
load-balancer, and monitoring sources. Application logs are written to
`/opt/skylicense/logs/latest.log`, roll daily or at 50 MiB, and enforce bounded
age, file-count, and aggregate-size retention on rollover.
