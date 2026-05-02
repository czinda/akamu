# Migration numbering

SQLite has an extra migration (`0006_mtc_log_index.sql`) that adds an index
for the MTC log table.  This migration has no equivalent in Postgres or MariaDB
because both databases create the index inline in the `CREATE TABLE` statement.

As a result, **SQLite numbering is one ahead** of Postgres/MariaDB from
migration 0007 onward:

| SQLite | Postgres / MariaDB | Description             |
|--------|--------------------|-------------------------|
| 0006   | —                  | mtc_log index (SQLite-only) |
| 0007   | 0006               | profile_grants          |
| 0008   | 0007               | audit_events            |
| 0009   | 0008               | operators               |

**Rule for future migrations:**
- SQLite: use the next number in `migrations/sqlite/` (currently `0010_…`)
- Postgres and MariaDB: use the next number in their directories (currently `0009_…`)

The divergence is intentional and permanent.  Do not attempt to renumber.
