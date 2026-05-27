# Ansible Playbooks — FreeIPA + Akamu

Automates the installation of a FreeIPA cluster with akamu deployed on every
node behind IPA's Apache httpd.  Akamu is installed from the
[abbra/synta COPR](https://copr.fedorainfracloud.org/coprs/abbra/synta/)
repository.

## Requirements

- Fedora 42+ on all target hosts
- Working forward and reverse DNS for every FQDN (IPA requires this)
- SSH key-based access with passwordless sudo
- On the control node:
  ```bash
  pip install ansible
  ansible-galaxy collection install freeipa.ansible_freeipa ansible.posix
  ```
  Or install `ansible-freeipa` from the distribution:
  ```bash
  # Fedora / RHEL
  dnf install ansible-freeipa
  ansible-galaxy collection install ansible.posix
  ```

## Quick start

```bash
# 1. Copy and edit the inventory.
cp inventory.ini.example inventory.ini
$EDITOR inventory.ini   # set hostnames, ipa_domain, ipa_realm, passwords

# 2. (Recommended) Encrypt passwords with ansible-vault.
ansible-vault encrypt_string 'SomeAdminPass1!' --name ipa_admin_password
ansible-vault encrypt_string 'SomeDSPass1!'    --name ipa_ds_password
# Paste the output into inventory.ini.

# 3. Run the full site playbook.
ansible-playbook -i inventory.ini site.yml

# Or run individual phases:
ansible-playbook -i inventory.ini playbooks/ipa_server.yml
ansible-playbook -i inventory.ini playbooks/ipa_replica.yml
ansible-playbook -i inventory.ini playbooks/akamu.yml
ansible-playbook -i inventory.ini playbooks/ipa_permissions.yml
```

## What gets installed

| Phase | Playbook | Target |
|---|---|---|
| 1 | `ipa_server.yml` | `ipa_server` group — runs `ipa-server-install` |
| 2 | `ipa_replica.yml` | `ipa_replicas` group — runs `ipa-replica-install`, serial |
| 3 | `akamu.yml` | `ipa_nodes` (all) — COPR, package, configs, service |
| 4 | `ipa_permissions.yml` | `ipa_server` (once) — grants required IPA privileges |

### IPA privileges granted by `ipa_permissions.yml`

For the basic deployment (gssproxy SPNEGO auth, own CA), no IPA LDAP privileges
are required — the KDC grants service tickets to IPA-enrolled principals without
additional configuration.

If the optional IPAThinCA profile integration is enabled
(`[profiles.providers.ipa]` in `akamu.toml`), the HTTP service principal needs
read access to the IPA CA LDAP subtree (`o=ipaca`).  On Fedora/RHEL IPA this
subtree is world-readable for IPA-enrolled principals, but the playbook creates
an explicit role assignment for clarity and forward compatibility.

| Privilege | Permissions | Purpose |
|---|---|---|
| `Akamu IPA CA Read` | `System: Read Certificate Profiles` | Read IPAThinCA profiles for ACME certificate issuance |

Standalone (non-replica) nodes additionally require Kerberos constrained
delegation if they perform S4U2Self-based LDAP profile fetches:

| IPA object | Setting | Purpose |
|---|---|---|
| `HTTP/<fqdn>@<REALM>` service | `ok_to_auth_as_delegate = true` | S4U2Self: impersonate authenticated users for LDAP binds |
| `akamu-delegation-targets` delegation target | `HTTP/` and `ldap/` principals of each IPA server | S4U2Proxy targets |
| `akamu-delegation` delegation rule | standalone HTTP principals | Assigns principals to the delegation target |

## Inventory variables

| Variable | Example | Description |
|---|---|---|
| `ipa_domain` | `ipa.example.com` | IPA DNS domain |
| `ipa_realm` | `IPA.EXAMPLE.COM` | Kerberos realm (usually uppercased domain) |
| `ipa_admin_password` | — | IPA `admin` account password |
| `ipa_ds_password` | — | LDAP Directory Manager password |
| `akamu_issuer_path` | `/acme` | URL path prefix for akamu behind Apache |

Additional defaults are in `group_vars/all.yml`.

## Post-installation

After `site.yml` completes:

- The ACME directory is at `https://<node-fqdn>/acme/acme/directory`
- Admin API: `https://<node-fqdn>/acme/admin/`
- The `admin@<REALM>` IPA principal is bootstrapped as the first akamu
  Administrator (see `bootstrap_operator_gssapi_principal` in `akamu.toml.j2`)

### Register an ACME account

IPA-enrolled services authenticate using their Kerberos ticket:

```bash
# Authenticate as a service principal (or kinit as a user).
kinit -k -t /etc/http.keytab HTTP/client.ipa.example.com@IPA.EXAMPLE.COM

# Register an ACME account using certbot or acme.sh.
# certbot negotiates SPNEGO automatically with --server pointing to akamu.
certbot register \
  --server https://ipa.example.com/acme/acme/directory \
  --agree-tos -m admin@example.com
```

### Request a certificate

```bash
certbot certonly \
  --server https://ipa.example.com/acme/acme/directory \
  --standalone -d client.ipa.example.com
```

## Troubleshooting

| Symptom | Check |
|---|---|
| akamu not starting | `journalctl -u akamu` — often a config parse error or missing DB dir |
| 502 Bad Gateway from Apache | `ls -la /run/akamu/` — socket must be group-accessible by `apache`; run `usermod -aG akamu apache` |
| gssproxy errors | `journalctl -u gssproxy` — verify `/etc/gssproxy/20-akamu.conf` is correct |
| SPNEGO returns 401 | Verify `GSS_USE_PROXY=yes` is being set: `journalctl -u akamu \| grep GSS_USE_PROXY` |
| Certificate issuance fails with profile errors | Enable the `[profiles.providers.ipa]` section and run `ipa_permissions.yml` |
| SELinux AVC denial for socket connect | `ausearch -m avc -ts recent` — may need `setsebool -P httpd_can_network_connect 1` or a custom policy |
