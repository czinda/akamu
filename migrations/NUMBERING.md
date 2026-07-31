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
| 0010   | 0009               | cert_subject_dn         |
| 0011   | 0010               | operator_lockout        |
| 0012   | 0011               | multi_ca                |
| 0013   | 0012               | cross_certs             |
| 0014   | 0013               | authz_ca_id             |
| 0015   | 0014               | operator_ca_scope       |
| 0016   | 0015               | email_challenge         |
| —      | 0015               | hot_indexes (Postgres-only) |
| 0017   | 0016               | delegation (RFC 9115)   |

| 0017   | 0016               | delegation (RFC 9115)   |
| 0018   | 0017               | eab_operator_owner      |
| 0019   | —/0018             | email_message_id_index  |
| 0020   | 0019/0019          | eab_bound_principal     |
| 0021   | 0020/0020          | eab_alg                 |
| —      | 0021/—             | eab_type_fixes (Postgres-only) |
| —      | 0022/—             | delegation_indexes (Postgres-only) |
| —      | 0023/0021          | eab_type_fixes / eab_alg (backend-specific) |
| —      | —/0022             | hot_indexes (MariaDB-only) |
| 0022   | 0024/0023          | node_keys               |
| 0023   | 0025/0024          | local_gen (CRDT delta gossip) |
| 0024   | 0026/0025          | crdt_cluster_nodes, crdt_order_owners, crdt_mtc_writer |
| 0025   | 0027/0026          | delegation_ca_id              |
| 0026   | 0028/0027          | tkauth (RFC 9447 JTI cache + challenge fields) |
| 0027–0030 | 0029–0032/0028–0031 | account_kerberos_principal, tkauth, tkauth_tkvalue, tkauth_ca_flag, mtc_per_ca |
| 0031   | 0033/0032          | drop audit_events (moved to journald namespace) |
| 0032   | 0034/0033          | revoked_ranges (MTC serial-number ranges) |
| 0033   | 0035/0034          | policy_rules (ABAC issuance policy)       |
| 0034   | 0036/0035          | policy_rules_tombstone (CRDT soft-delete)  |
| 0035   | 0037/0036          | policy_rules_unique_fix (partial unique index) |
| 0036   | 0038/0037          | authz_order_id_nullable (RFC 8555 §7.4.1 pre-authorization fix) |

**Rule for future migrations:**
- SQLite: use the next number in `migrations/sqlite/` (currently `0037_…`)
- Postgres: use the next number in `migrations/postgres/` (currently `0039_…`)
- MariaDB: use the next number in `migrations/mariadb/` (currently `0038_…`)

The divergence is intentional and permanent.  Do not attempt to renumber.
