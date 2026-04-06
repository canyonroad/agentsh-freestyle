# agentsh + Freestyle Demo

agentsh provides policy-driven runtime governance for AI agents — blocking dangerous commands, filtering environment variables, enforcing network rules, and maintaining a full audit trail. Freestyle provides fast VM isolation with snapshot-based startup. Together they form a defense-in-depth stack for running untrusted AI agent code safely.

## Prerequisites

- Node.js 18+
- Freestyle API key (from [freestyle.sh](https://freestyle.sh) dashboard)

## Quick Start

```bash
git clone <repo>
cd agentsh-freestyle
npm install
cp .env.example .env
# Edit .env with your FREESTYLE_API_KEY
npx tsx src/demo-blocking.ts
```

## Available Scripts

| Command | Description |
|---|---|
| `npm test` | Run full test suite (76 tests, 12 categories) |
| `npm run build-snapshot` | Bake VM image for faster startup |
| `npm run demo:blocking` | Command + filesystem blocking demo |
| `npm run demo:network` | Network policy demo |
| `npm run demo:audit` | Audit trail logging demo |
| `npm run demo:quarantine` | Soft-delete and file recovery demo |
| `npm run demo:env` | Environment variable filtering demo |
| `npm run demo:detect` | Security capability detection demo |
| `npm run demo:attack` | Red team simulation (44 attacks) |
| `npm run demo:resources` | Resource limits demo |
| `npm run demo:multi-context` | Multi-context command blocking demo |
| `npm run demo:fuse` | FUSE/VFS file protection demo |

## Image Baking

`build-snapshot.ts` creates a Freestyle VM snapshot with agentsh pre-installed. Subsequent VM creations restore from this snapshot instead of reinstalling from scratch, cutting startup time significantly.

```bash
npm run build-snapshot
# Output:
# Snapshot ID: snap_xxxxxxxxxxxxxxxx
```

Use the snapshot ID in your own VMs:

```typescript
const { vm } = await freestyle.vms.create({ snapshotId: 'snap_xxxxxxxxxxxxxxxx' })
```

## Architecture

### VmAgentsh Integration (`src/vm-agentsh.ts`)

`VmAgentsh` extends the Freestyle `VmWith` class and hooks into two lifecycle points:

- **`configureSnapshotSpec`** — installs the agentsh `.deb`, creates required directories, and configures `sudo` rules. This runs once during snapshot baking so the cost is not paid on every VM creation.
- **`configureSpec`** — uploads `config.yaml`, `default.yaml`, and `agentsh-startup.sh` into each VM and registers the agentsh systemd service. This runs on every VM creation using the snapshot as a base.

### Security Stack (5 Layers)

| Layer | Description |
|---|---|
| **Shell Shim** | Replaces `/bin/bash` with an agentsh shim that intercepts every command before execution |
| **FUSE** | Mounts a virtual filesystem layer that enforces file operation rules (allow, deny, soft-delete) at the kernel boundary |
| **Landlock** | Linux LSM-based filesystem sandboxing that restricts process access to approved path sets |
| **BASH_ENV** | Intercepts shell environment at startup to enforce variable allowlists/denylists and block enumeration |
| **Network Proxy** | Transparent proxy that enforces network rules — blocking metadata endpoints, private networks, and unapproved destinations |

### Config Files

| File | Purpose |
|---|---|
| `config.yaml` | agentsh server settings: HTTP/gRPC addresses, session limits, audit storage, sandbox flags |
| `default.yaml` | Security policy (~640 lines): file rules, network rules, command rules, environment policy, resource limits |
| `agentsh-startup.sh` | Bootstrap script: restricts `/dev/fuse` before snapshot, starts agentsh server, installs shell shim |

## Security Policy Overview

The `default.yaml` policy follows a default-deny posture with an explicit allowlist.

**File rules (18 rules)**
- Workspace (`/workspace`, `$PROJECT_ROOT`) — read/write allowed; deletes are soft (quarantined, recoverable)
- `/tmp` — read/write allowed
- `/etc`, `/root`, credential files — blocked; any credential access triggers an approval request

**Network rules (11 rules)**
- Localhost and loopback — allowed
- Public package registries (npm, PyPI, apt) — allowed
- AWS/GCP/Azure metadata endpoints (`169.254.169.254`, etc.) — blocked
- Private networks (RFC 1918) — blocked

**Command rules (10 rules)**
- Standard POSIX tools, package managers, dev tools — allowed
- Dangerous commands (`curl | bash`, `dd`, `mkfs`, privilege escalation) — blocked

**Environment policy**
- Allowlist of known-safe variables passed through; all others stripped
- `env`, `printenv`, and variable enumeration patterns — blocked

**Resource limits**
- Memory: 2 GB, no swap
- CPU: 50% quota
- PIDs: 100 max
- Disk I/O: 50 MB/s read, 25 MB/s write
- Command timeout: 5 min; session timeout: 1 hour

## Related

- [e2b-agentsh](https://github.com/erans/e2b-agentsh) — same demo using E2B sandboxes
- [agentsh](https://github.com/erans/agentsh) — the agentsh runtime governance tool
