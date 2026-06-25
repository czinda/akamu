# Hardened Container Deployment

This guide covers deploying akamu using hardened OCI container images built on
the [Hummingbird](https://hummingbird-project.io/) minimal image project.
It applies to both local development (podman-compose) and production
(Kubernetes/OpenShift) environments.

## Image Architecture

Akamu produces five container images, all following the same hardening pattern:

| Image | Binary | Purpose |
|-------|--------|---------|
| `akamu` | `akamu` | ACME CA server |
| `akamu-cosigner` | `akamu-cosigner` | MTC checkpoint cosigner daemon |
| `akamu-cli` | `akamu-cli` | ACME client CLI |
| `akamuctl` | `akamuctl` | Server administration CLI |
| `akamu-proxy` | nginx | TLS-terminating reverse proxy |

### Multi-Stage Build

Every image uses a two-stage build:

1. **Builder** (`quay.io/hummingbird/rust:latest-builder`) — compiles the Rust
   binary with all build dependencies (git, clang, openssl-devel, sqlite-devel).
2. **Runtime** (`quay.io/hummingbird/core-runtime:latest-openssl`) — minimal
   Fedora userland with only runtime libraries (openssl-libs, sqlite-libs,
   ca-certificates).

The runtime image contains no compilers, no -devel headers, no git, and no
cargo.  This eliminates approximately 800 MB of attack surface.

### Hardening Measures

Every image enforces:

- **Non-root user** — runs as UID 1001 (`akamu`), compatible with OpenShift's
  arbitrary UID policy.
- **No SUID/SGID binaries** — all set-user-ID and set-group-ID bits are removed.
- **Read-only rootfs** — all writes go to the `/app/data` volume; the container
  filesystem is mounted read-only at runtime.
- **Minimal packages** — no curl, wget, nc, or other diagnostic tools that an
  attacker could exploit.
- **OCI provenance labels** — every image carries `org.opencontainers.image.*`
  labels for supply chain traceability.

## Building the Images

```bash
# Server
podman build -t akamu:latest -f Containerfile .

# Cosigner
podman build -t akamu-cosigner:latest -f contrib/containers/Containerfile.cosigner .

# CLI tools
podman build -t akamu-cli:latest -f contrib/containers/Containerfile.cli .
podman build -t akamuctl:latest -f contrib/containers/Containerfile.akamuctl .

# Reverse proxy
podman build -t akamu-proxy:latest -f contrib/containers/Containerfile.proxy .
```

## Podman-Compose (Dev/Test)

The `podman-compose.yml` at the project root deploys a complete stack with:

- **akamu** — ACME server (port 8080 on internal network)
- **cosigner-a / cosigner-b** — two MTC cosigners on the internal network
- **proxy** — nginx reverse proxy (port 443 on the host)

### Network Segmentation

```
                  ┌───────────────────────────────────────────┐
                  │          akamu-external                    │
Internet ──443──▶ │   proxy ──8080──▶ akamu                   │
                  └──────────────────┬────────────────────────┘
                                     │
                  ┌──────────────────┴────────────────────────┐
                  │      akamu-internal (internal: true)       │
                  │                                            │
                  │   akamu ──8080──▶ cosigner-a              │
                  │          ──8080──▶ cosigner-b              │
                  │          ──5432──▶ postgres (optional)     │
                  └────────────────────────────────────────────┘
```

The `akamu-internal` network is declared with `internal: true`, making
cosigners and PostgreSQL unreachable from outside the compose stack.

### Security Constraints

Every service in the compose file runs with:

```yaml
user: "1001:1001"
read_only: true
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 512M
```

### Starting the Stack

```bash
# Generate TLS certificates for the proxy (self-signed for dev)
mkdir -p contrib/containers/configs/tls-certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout contrib/containers/configs/tls-certs/server.key \
  -out contrib/containers/configs/tls-certs/server.pem \
  -days 365 -nodes -subj "/CN=localhost"

# Start the stack
podman-compose up -d

# Verify all services are healthy
podman-compose ps

# Test the ACME directory
curl -k https://localhost/acme/directory
```

## Kubernetes / OpenShift

Kubernetes manifests live in `contrib/kubernetes/` using Kustomize:

```
contrib/kubernetes/
├── base/                    # Shared manifests
│   ├── namespace.yaml       # Restricted Pod Security Standard
│   ├── akamu-deployment.yaml
│   ├── cosigner-deployment.yaml
│   ├── networkpolicy.yaml   # Default-deny + per-component whitelists
│   ├── rbac.yaml            # Minimal service accounts
│   └── ...
└── overlays/
    ├── dev/                 # 1 replica, relaxed limits
    ├── staging/             # 2 replicas
    └── production/          # 3 replicas, tightened requests
```

### Pod Security

The akamu namespace enforces the Kubernetes **Restricted** pod security
standard:

```yaml
pod-security.kubernetes.io/enforce: restricted
```

All pods run with:
- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: ["ALL"]`
- `seccompProfile.type: RuntimeDefault`
- `automountServiceAccountToken: false`

### Network Policies

A default-deny policy blocks all traffic.  Per-component policies then
whitelist only the traffic that each service needs:

| Source | Destination | Port | Purpose |
|--------|-------------|------|---------|
| Ingress controller | akamu | 8080 | ACME client traffic |
| akamu | cosigner | 8080 | MTC checkpoint signing |
| akamu | postgres | 5432 | Database queries |
| akamu | akamu | 9443 | Gossip replication |
| akamu | internet | 53, 80, 443, 853 | DNS, http-01 validation |
| cosigner | (none) | — | No egress allowed |

### Deploying

```bash
# Development
kubectl apply -k contrib/kubernetes/overlays/dev/

# Staging
kubectl apply -k contrib/kubernetes/overlays/staging/

# Production (3-node gossip cluster)
kubectl apply -k contrib/kubernetes/overlays/production/
```

## Cluster Topology

For multi-node deployments with CRDT gossip replication, each akamu pod
maintains its own database and replicates ACME state to peers.  See
[Cluster Setup and Gossip](../admin/cluster.md) for configuration details.

```
        ┌──────────┐     ┌──────────┐     ┌──────────┐
        │ akamu-0  │◄───▶│ akamu-1  │◄───▶│ akamu-2  │
        │(gossip)  │     │(gossip)  │     │(gossip)  │
        └────┬─────┘     └────┬─────┘     └────┬─────┘
             │                │                 │
        ┌────▼────┐      ┌───▼─────┐     ┌────▼────┐
        │cosigners│      │cosigners│     │cosigners│
        └─────────┘      └─────────┘     └─────────┘
```

## Cryptographic Hardening

### Post-Quantum Keys

The hardened config profiles enable ML-DSA-65 (FIPS 204) for the CA signing
key.  The Hummingbird runtime image includes PQC-capable OpenSSL 3.x:

```toml
[ca]
key_type = "ml-dsa-65"
hash_alg = "sha384"
```

### HSM Integration

For production, store the CA private key in an HSM via PKCS#11:

```toml
[ca]
key_file = "pkcs11:token=akamu-ca;object=ca-signing-key;type=private"
require_encrypted_key = true
```

### Internal mTLS

All inter-service communication should use mutual TLS.  Configure
`require_tls = true` in the database section and TLS 1.3 for the server:

```toml
[database]
require_tls = true

[tls]
protocols = ["TLSv1.3"]
```

## Seccomp Profile

A restricted seccomp profile is provided at
`contrib/containers/seccomp/akamu.json`.  It allows only the syscalls that a
Rust async server needs and explicitly blocks dangerous operations (ptrace,
mount, module loading, namespace manipulation).

Use it with podman:

```bash
podman run --security-opt seccomp=contrib/containers/seccomp/akamu.json \
  akamu:latest
```

Or in Kubernetes, set the pod's seccomp profile to a custom `LocalhostProfile`.

## Configuration Profiles

Four hardened configuration profiles are provided in `contrib/configs/`:

| Profile | Database | Cluster | PQC | HSM |
|---------|----------|---------|-----|-----|
| `hardened-sqlite.toml` | SQLite | No | No | No |
| `hardened-postgres.toml` | PostgreSQL + TLS | No | No | No |
| `hardened-cluster.toml` | PostgreSQL + TLS | Yes (gossip) | ML-DSA-65 | No |
| `hardened-hsm.toml` | PostgreSQL + TLS | Yes (gossip) | ML-DSA-65 | PKCS#11 |

All profiles enable:
- Encrypted CA key enforcement (`require_encrypted_key = true`)
- DNSSEC validation
- External Account Binding (EAB)
- CAA identity checking
- Audit log halt-on-overflow
- Session lockout after failed authentication

## CI Security Pipeline

The CI workflow (`.github/workflows/ci.yml`) includes a `container-scan` job
that runs after tests pass:

1. Builds both the server and cosigner hardened images
2. Verifies non-root user, no build tools, no SUID binaries, read-only rootfs
3. Scans for HIGH/CRITICAL CVEs with `trivy`
4. Generates SPDX and CycloneDX SBOMs with `syft`
5. Reports image sizes

## Verification

After deploying, verify the hardening is effective:

```bash
# 1. Confirm non-root
podman exec akamu id
# uid=1001(akamu) gid=1001(akamu)

# 2. Confirm no build tools
podman exec akamu which cargo gcc git
# (should all fail)

# 3. Confirm read-only rootfs
podman exec akamu touch /test
# touch: cannot touch '/test': Read-only file system

# 4. Confirm network isolation (cosigner not reachable from host)
curl http://cosigner-a:8080/
# curl: (6) Could not resolve host: cosigner-a

# 5. Confirm ACME directory is reachable via proxy
curl -k https://localhost/acme/directory
# {"newNonce":"...", "newAccount":"...", ...}
```
