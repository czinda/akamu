# Backup and Restore

This runbook describes how to back up an akamu deployment and restore it
to a known-good state after hardware failure, corruption, or disaster
recovery.

## What to back up

| Asset | Location | Notes |
|-------|----------|-------|
| Database | `database.url` in config | SQLite file or PostgreSQL/MariaDB dump |
| CA private key(s) | `[[ca]] key_file` | PEM or PKCS#11 — see below; one entry per configured CA |
| CA certificate(s) | `[[ca]] cert_file` | PEM; one entry per configured CA |
| Admin TLS key/cert | `admin.key_file`, `admin.cert_file` | If not auto-generated |
| Configuration file | `akamu.toml` | Server configuration |
| MTC log directory | `mtc.log_path` | Only if MTC is enabled |
| Cosigner config & key | `akamu-cosigner.toml` + key file | If cosigner is deployed |

## Database backup

### SQLite

SQLite in WAL mode supports online backup.  Use the `.backup` command
while the server is running:

```sh
sqlite3 /var/lib/akamu/db.sqlite3 ".backup /var/backups/akamu/db-$(date +%F).sqlite3"
```

Alternatively, stop the server and copy the database file and its WAL/SHM
companions:

```sh
systemctl stop akamu
cp /var/lib/akamu/db.sqlite3{,-wal,-shm} /var/backups/akamu/
systemctl start akamu
```

### PostgreSQL

Use `pg_dump` for logical backups:

```sh
pg_dump -Fc akamu > /var/backups/akamu/db-$(date +%F).pgdump
```

For point-in-time recovery, configure WAL archiving and base backups per
the [PostgreSQL documentation](https://www.postgresql.org/docs/current/continuous-archiving.html).

### MariaDB

Use `mariadb-dump` (or `mysqldump`):

```sh
mariadb-dump --single-transaction akamu > /var/backups/akamu/db-$(date +%F).sql
```

## Key material backup

### File-based keys

Copy the PEM files to secure offline storage:

```sh
cp /etc/akamu/ca.key.pem /var/backups/akamu/
cp /etc/akamu/ca.cert.pem /var/backups/akamu/
chmod 600 /var/backups/akamu/ca.key.pem
```

When `ca.require_encrypted_key` is enabled, also back up the
password file referenced by `ca.key_password_file`.

### PKCS#11 / HSM keys

HSM key backup procedures are device-specific.  Consult your HSM
vendor's documentation for key export or key wrapping operations.
Ensure the wrapped key material is stored separately from the HSM.

## Restore procedure

1. **Stop the server:**

   ```sh
   systemctl stop akamu
   ```

2. **Restore the database:**

   - SQLite: copy the backup file to the configured path.
   - PostgreSQL: `pg_restore -d akamu /var/backups/akamu/db-YYYY-MM-DD.pgdump`
   - MariaDB: `mariadb akamu < /var/backups/akamu/db-YYYY-MM-DD.sql`

3. **Restore key material and configuration:**

   ```sh
   cp /var/backups/akamu/ca.key.pem /etc/akamu/
   cp /var/backups/akamu/ca.cert.pem /etc/akamu/
   cp /var/backups/akamu/akamu.toml /etc/akamu/
   chmod 600 /etc/akamu/ca.key.pem
   ```

4. **Verify schema version:**

   The server applies pending migrations automatically on startup.
   No manual migration step is required.

5. **Start the server:**

   ```sh
   systemctl start akamu
   ```

6. **Regenerate the CRL:**

   After restoring from backup, the CRL may be stale.  Force
   regeneration:

   ```sh
   akamuctl crl-force
   ```

7. **Verify the server is healthy:**

   ```sh
   akamuctl stats
   ```

   Confirm certificate and account counts match expectations.

## Disaster recovery testing

Periodically verify that backups can be restored to a staging
environment:

1. Provision a clean staging host.
2. Restore the database and key material from the latest backup.
3. Start the server with the production configuration (adjusted for
   the staging listener address).
4. Run `akamuctl stats` and compare counts against production.
5. Issue a test certificate using `akamu-cli` to confirm end-to-end
   functionality.

Schedule this verification at least quarterly, or after any change to
the backup pipeline.

## Rotation and retention

- Keep at least **7 daily** and **4 weekly** database backups.
- Rotate backups using your preferred tool (`logrotate`, cron cleanup
  script, or cloud object lifecycle rules).
- Store backups on a different host or storage system from the
  production server.
- Encrypt backup archives at rest using `gpg` or your storage
  provider's server-side encryption.
