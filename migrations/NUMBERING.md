# Migration numbering

Each backend's migration history was squashed into a single
`0001_initial.sql` (no production deployment existed yet, so migration-replay
compatibility did not need to be preserved). All three backends now start
from `0001_initial.sql` with an identical schema, including CHECK
constraints on the `status` column of `accounts`, `orders`, `authorizations`,
`challenges`, and `certificates`.

The previous numbering divergence between backends (documented in this file
before the squash) no longer applies — it only existed because SQLite had one
extra migration for an index that Postgres/MariaDB created inline. That
history is gone; going forward, keep backend numbering in sync file-for-file
whenever a change affects all three.

**Rule for future migrations:**
- SQLite: use the next number in `migrations/sqlite/` (currently `0002_…`)
- Postgres: use the next number in `migrations/postgres/` (currently `0002_…`)
- MariaDB: use the next number in `migrations/mariadb/` (currently `0002_…`)

Renumbering after a squash is a one-time operation. Do not squash again once
this branch has a real production deployment — from that point on, migrations
must be additive and forward-only like any other project.
