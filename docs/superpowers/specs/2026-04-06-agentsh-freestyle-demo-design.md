# agentsh + Freestyle Demo Design

## Overview

A comprehensive security demo showcasing agentsh runtime governance within Freestyle VMs. Modeled after the E2B reference implementation (`e2b-agentsh`), adapted to use Freestyle's TypeScript SDK and its `VmWith` custom integration system.

**Value proposition:** Freestyle provides fast VM isolation (<700ms provisioning). agentsh adds policy-driven governance (command blocking, network filtering, file I/O interception, secret redaction, audit logging). Together they create defense-in-depth security for untrusted AI agent code.

## Project Structure

```
agentsh-freestyle/
├── package.json                    # freestyle-sandboxes, tsx, typescript
├── tsconfig.json
├── .env.example                    # FREESTYLE_API_KEY placeholder
├── .gitignore
├── README.md
├── config.yaml                     # agentsh server config
├── default.yaml                    # agentsh security policy
├── agentsh-startup.sh              # Server startup + shim install script
├── src/
│   ├── vm-agentsh.ts               # VmAgentsh custom integration class
│   ├── helpers.ts                  # Shared test helpers (formatting, assertions)
│   ├── test-template.ts            # Comprehensive test suite (64 tests)
│   ├── build-snapshot.ts           # Image baking: creates agentsh snapshot
│   ├── diag-kernel.ts              # Ground-truth kernel probe (bare vs agentsh VM)
│   ├── diag-kernel.sh              # Kernel probe shell payload (run via vm.exec)
│   ├── demo-blocking.ts            # Command/filesystem blocking demo
│   ├── demo-audit.ts               # Audit trail demo
│   ├── demo-network.ts             # Network policy demo
│   ├── demo-quarantine.ts          # Soft-delete/file recovery demo
│   ├── demo-env-filtering.ts       # Environment variable filtering demo
│   ├── demo-detect.ts              # Security capability detection demo
│   ├── demo-attack-sim.ts          # Red team simulation (44 attacks)
│   ├── demo-resource-limits.ts     # Resource limits demo
│   ├── demo-multi-context.ts       # Multi-context command blocking demo
│   └── demo-fuse-protection.ts     # FUSE/VFS file protection demo
```

## Dependencies

```json
{
  "freestyle-sandboxes": "latest",
  "tsx": "^4.21.0",
  "typescript": "^5.9.3"
}
```

Environment: `FREESTYLE_API_KEY` from Freestyle Dashboard.

## VmAgentsh Custom Integration

The core differentiator. A `VmWith` subclass encapsulating agentsh installation and lifecycle.

### VmAgentshInstance (runtime interface)

```typescript
class VmAgentshInstance extends VmWithInstance {
  // Wait for agentsh server health check (http://127.0.0.1:18080/health)
  async waitReady(retries = 20, intervalMs = 1000): Promise<void>

  // Execute command through shell shim, returns structured result
  async exec(command: string, timeoutMs = 30000): Promise<{
    stdout: string;
    stderr: string;
    exitCode: number;
    blocked: boolean;  // true if exitCode === 126
  }>

  // Run a named test with pass/fail output
  async test(description: string, command: string, expect: {
    blocked?: boolean;
    exitCode?: number;
    stdoutContains?: string;
    stdoutNotContains?: string;
  }): Promise<boolean>
}
```

### VmAgentsh (setup/configuration)

```typescript
class VmAgentsh extends VmWith<VmAgentshInstance> {
  // configureSnapshotSpec: heavy work, cached across VM creates
  //   - Download agentsh v0.16.9 binary → /usr/bin/agentsh
  //   - Download agentsh-shell-shim → /usr/bin/agentsh-shell-shim
  //   - Install deps: fuse3, libseccomp2, ca-certificates, curl
  //   - Create dirs: /etc/agentsh/policies, /var/lib/agentsh/*, /var/log/agentsh

  // configureSpec: per-VM config
  //   - Copy config.yaml → /etc/agentsh/config.yaml
  //   - Copy default.yaml → /etc/agentsh/policies/default.yaml
  //   - Copy agentsh-startup.sh → /opt/agentsh-startup.sh

  // systemd services:
  //   - agentsh (service): runs /opt/agentsh-startup.sh (server + shim in one script)
}
```

### Key design decisions

- `configureSnapshotSpec` handles binary download and apt installs (slow, cacheable)
- `configureSpec` handles policy files (fast, per-VM)
- `blocked: boolean` convenience field derived from exit code 126
- `test()` provides formatted pass/fail output matching E2B demo style
- All commands go through `vm.exec()` — shell shim auto-intercepts, no agentsh HTTP API needed

## agentsh Installation & Startup Flow

### Snapshot layer (cached)

1. Download agentsh v0.16.9 binary from GitHub releases to `/usr/bin/agentsh`
2. Download `agentsh-shell-shim` to `/usr/bin/agentsh-shell-shim`
3. Install system deps: `fuse3`, `libseccomp2`, `ca-certificates`, `curl`
4. Create directories: `/etc/agentsh/policies`, `/var/lib/agentsh/quarantine`, `/var/lib/agentsh/sessions`, `/var/log/agentsh`

### Per-VM layer

1. Copy `config.yaml` to `/etc/agentsh/config.yaml`
2. Copy `default.yaml` to `/etc/agentsh/policies/default.yaml`
3. Copy `agentsh-startup.sh` to `/opt/agentsh-startup.sh`

### Systemd services

Single service: `agentsh` (service mode) — runs `/opt/agentsh-startup.sh` which handles server startup, health check, and shim installation in sequence. See startup script section below for details.

### Startup script (`agentsh-startup.sh`)

Used by the `agentsh-server` systemd service as its `ExecStart` command. It handles everything in sequence rather than splitting across multiple systemd units:

1. Sets FUSE device permissions (`chmod 666 /dev/fuse` if available)
2. Starts agentsh server in background with logging to `/var/log/agentsh/server.log`
3. Health check loop on `http://127.0.0.1:18080/health` (waits for server ready)
4. Installs shell shim (`agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash`)
5. Warms up shim with `echo shim warmup ok`

Environment variables set via systemd `Environment=`:
- `AGENTSH_SHIM_FORCE=1`
- `AGENTSH_SERVER=http://127.0.0.1:18080`

This is a single systemd service (not two separate ones) because the shim install depends on the server being healthy, and running it all in one script is simpler than coordinating two systemd units with health-check dependencies.

### Image baking (`build-snapshot.ts`)

Alternative approach for faster startup:
1. Creates a VM via VmSpec with agentsh fully installed
2. Waits for readiness
3. Calls `vm.snapshot()` to capture the state
4. Prints snapshot ID for reuse
5. Users can then create VMs from snapshot ID, skipping installation

## Test Suite (test-template.ts)

64 tests across 14 categories. (Design originally called for ~76 across 12 categories; implementation consolidated some overlaps during the Freestyle port and added two new categories for kernel ground-truth probes.)

| Category | Count | What it validates |
|---|---|---|
| Installation | 2 | agentsh binary exists, seccomp support |
| Server & Config | 6 | Server healthy, process running, policy/config files exist, FUSE/seccomp enabled |
| Shell Shim | 4 | Shim installed, real bash preserved, echo/python through shim |
| Policy Evaluation | 9 | Static policy-test CLI (sudo denied, echo allowed, workspace write, soft-delete, SSH approval) |
| Security Diagnostics | 4 | `agentsh detect` — seccomp, cgroups_v2, landlock availability |
| **Kernel capabilities vs detect** *(new, 2026-04-08)* | 6 | Ground-truth kernel probes independent of `agentsh detect`: `CAP_BPF` in server `CapEff`, `#196` ebpf guard, `#197` cgroup base_path workaround active, `/sys/fs/cgroup/agentsh` exists, process cgroup under `/agentsh/`, PID limit enforced |
| Command Blocking (direct API) | 7 | sudo, su, ssh, kill, rm -rf blocked; echo, ls allowed — uses `execDirect()` so `command_rules` actually evaluate |
| Network Blocking | 5 | npmjs allowed, metadata blocked, evil.com blocked, private networks blocked |
| Environment Policy | 3 | Safe vars present (HOME/PATH), BASH_ENV or AGENTSH vars set |
| File I/O | 4 | Workspace writes allowed, /tmp writes allowed, Python workspace writes, /etc writes (Landlock gap documented) |
| Multi-context (documents bypass) | 4 | sudo/env-sudo inside bash.real succeed on root VM — documents the sub-command bypass model |
| FUSE Workspace & Soft Delete | 4 | File creation, soft-delete, file gone from original, quarantine directory |
| Credential Path | 3 | ~/.ssh, ~/.aws read fails; /proc/1/environ readable (Landlock gap documented) |
| Audit | 2 | SQLite db exists, command events recorded |

**Current stability:** runs land at 58–60 passing out of 64. The 4–6 remaining failures are pre-existing session-API timing flakes — different tests fail each run (`agentsh installed`, `server healthy`, `policy file exists`, FUSE soft-delete sequence, occasional `INTERNAL_ERROR`). Not correlated with the 2026-04-08 config/startup changes; the commit `275dfd0` "58/58 passing" claim was a single lucky run. The six new kernel-capability tests pass consistently (6/6 across three runs).

## Demo Files

Each is a standalone script: creates VM, runs focused demos, cleans up.

| File | Purpose | Key scenarios |
|---|---|---|
| `demo-blocking.ts` | Command + filesystem policy | 11 sections: sudo blocked, file writes blocked, allowed ops |
| `demo-audit.ts` | Audit trail logging | Query SQLite audit DB, show event stream |
| `demo-network.ts` | Network policy | localhost allowed, metadata blocked, registries allowed, evil.com blocked |
| `demo-quarantine.ts` | Soft-delete & recovery | rm moves to quarantine, `agentsh trash list`, `agentsh trash restore` |
| `demo-env-filtering.ts` | Env var filtering | Sensitive vars stripped, allowlist/denylist, enumeration blocked |
| `demo-detect.ts` | Security capabilities | `agentsh detect` — shows available kernel security features |
| `demo-attack-sim.ts` | Red team simulation | 44 attacks across 6 phases: recon, cred theft, privesc, lateral movement, data exfil, persistence |
| `demo-resource-limits.ts` | Resource limits | PID bomb, memory exhaustion, CPU quota, disk I/O caps |
| `demo-multi-context.ts` | Multi-context blocking | sudo via env, xargs, find -exec, python, bash builtins |
| `demo-fuse-protection.ts` | FUSE/VFS protection | cp/dd/tee/mkdir to /etc blocked, python file I/O blocked, workspace allowed |

## Config Files

### config.yaml

Adapted from E2B reference:

- **Server:** HTTP on `127.0.0.1:18080`, gRPC on `127.0.0.1:9090`
- **FUSE:** Enabled with deferred mounting (for VM snapshot compatibility)
- **Landlock:** Enabled for execution restrictions
- **env_inject:** `BASH_ENV`, `AGENTSH_SERVER`, `HTTPS_PROXY`, `AGENTSH_SHIM_FORCE=1`
- **DLP:** Redact API keys, credit cards, SSN, JWT, AWS creds, GitHub/Slack tokens, private keys, custom patterns for OpenAI/Anthropic/Freestyle keys
- **Audit:** SQLite at `/var/lib/agentsh/events.db`, 90-day retention

### default.yaml (~700 lines)

Security policy adapted from E2B reference:

**File rules (25):**
- Workspace read/write allowed
- /tmp full access
- /etc, /usr/bin write denied
- Credentials (~/.ssh, ~/.aws, ~/.gcloud, .env) require approval
- Soft-delete on rm in workspace
- Default: deny all

**Network rules (16):**
- Localhost allowed
- Package registries allowed (npm, PyPI, Cargo, Go)
- Code hosting allowed (GitHub, GitLab, Bitbucket)
- Private networks blocked (10.x, 172.16.x, 192.168.x)
- Cloud metadata blocked (169.254.169.254, 100.100.100.200)
- Malicious domains blocked (evil.com)
- Unknown HTTPS/HTTP require approval

**Command rules (13+):**
- Safe commands allowed (bash, sh, ls, cat, grep, pwd, echo, date, which)
- Dev tools allowed (git, node, npm, python, pip, cargo, go, make)
- Git safety: force-push, direct main/master push, hard reset, forced clean blocked
- Network tools: curl/wget allowed direct only, nested requires approval
- Package install requires approval
- Dangerous commands blocked (nc, netcat, ssh, rsync, dd, kill, sudo, su, chroot, unshare)
- Bash builtins blocked (kill, enable, ulimit) via BASH_ENV secondary enforcement
- Catch-all: allow other commands

**Environment policy:**
- Allowlist: HOME, PATH, USER, SHELL, TERM, LANG, HOSTNAME, HTTPS_PROXY, AGENTSH_*
- Denylist: FREESTYLE_API_KEY, *_SECRET*, *_TOKEN, *_KEY, *_PASSWORD, DATABASE_URL
- Block env iteration (env, printenv)

**Resource limits:**
- Max memory: 2048 MB, no swap
- CPU quota: 50%
- Max processes: 100
- Disk read: 50 MB/s, write: 25 MB/s
- Command timeout: 5m
- Session timeout: 1h
- Idle timeout: 15m

## Error Handling & Cleanup

- Each demo wraps work in try/finally to ensure VM cleanup even on failure
- `VmAgentshInstance.exec()` has configurable timeout (default 30s), throws on timeout
- `waitReady()` retries with backoff, throws clear error after max retries with diagnostic info
- Test failures are non-fatal — all tests run to completion, summary printed at end

## VM Lifecycle Per Demo

1. `freestyle.vms.create({ spec: new VmSpec({ with: { agentsh: new VmAgentsh() } }) })`
2. `vm.agentsh.waitReady()` — polls health endpoint
3. Run tests/demos
4. Print summary
5. Cleanup in finally block

## Developer Experience

- Each demo independently runnable: `npx tsx src/demo-blocking.ts`
- Full test suite: `npx tsx src/test-template.ts`
- Image baking: `npx tsx src/build-snapshot.ts`
- `package.json` scripts for all of the above
- `.env.example` with `FREESTYLE_API_KEY=your_key_here`
- README with quickstart, prerequisites, and description of each demo

## Execution Approach

All commands go through `vm.exec()` which is auto-intercepted by the agentsh shell shim. No agentsh HTTP session API calls needed. This is the simplest integration pattern and matches how real AI agents would interact with the sandbox.

Exit code meanings:
- `0` — command allowed and succeeded
- `126` — command blocked by agentsh policy (EACCES/permission denied)
- Non-zero (other) — command ran but failed

## Security Stack (5 layers)

1. **Shell Shim:** `/bin/bash` replaced by `agentsh-shell-shim`, intercepts all bash commands
2. **FUSE:** Filesystem interception at VFS level, protects against tool-level bypasses (cp, dd, python file I/O)
3. **Landlock:** Kernel-level execution restrictions, whitelisted binary paths only
4. **BASH_ENV:** Disables dangerous bash builtins (kill, enable, ulimit) at shell startup
5. **Network Proxy:** HTTPS traffic interception via embedded proxy, domain/IP filtering

## Kernel Reality vs agentsh Detect (2026-04-08)

Added after a direct kernel capability probe (`src/diag-kernel.ts` + `src/diag-kernel.sh`) run on a raw Freestyle VM AND on an agentsh-provisioned VM side-by-side. The diag script uses `vm.exec()` directly — it does not touch the agentsh HTTP API — so it can distinguish between "the kernel doesn't have it" and "agentsh can't see it."

### What the kernel actually provides

Verified on kernel `6.1.0-6-freestyle`:

- **BPF**: `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`. `bpftool feature probe kernel` reports `bpf() syscall is available` and lists 29+ program types. Raw `syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr))` with a minimal socket-filter program returns `fd=3`. systemd already has 9 BPF progs loaded at boot (`sd_devices`, `sd_fw_egress`, `sd_fw_ingress`).
- **Capabilities**: the agentsh server process runs with `CapEff=0x1ffffffffff` — every bit set, including `cap_bpf`, `cap_perfmon`, `cap_net_admin`, `cap_sys_admin`. `capsh --decode` confirms.
- **cgroups v2**: mounted at `/sys/fs/cgroup` with `nsdelegate memory_recursiveprot`. The root `cgroup.subtree_control` delegates `cpuset cpu io memory hugetlb pids rdma misc`. `mkdir /sys/fs/cgroup/<new>` + writing `memory.max`, `pids.max`, `cpu.max` all succeed at the root.
- **LSMs**: `capability,selinux`. **No Landlock**, no Yama. This remains a genuine kernel-side gap.

### What agentsh detect reports on the same VM

`agentsh detect` (v0.16.9) ran on an agentsh-provisioned VM reports:

- **Network 0/20**: `ebpf - permission denied`. Wrong — the server has `cap_bpf` and `bpf()` works. Forcing `sandbox.network.ebpf.enabled: true` makes the server refuse to start because the same broken detect path runs as a startup gate. Upstream: **canyonroad/agentsh#196**.
- **Resource Limits 15/15**: scored as enforced, but in the default configuration agentsh places per-command cgroups under `/sys/fs/cgroup/system.slice/freestyle-supervisor.service/agentsh/...` where `cgroup.subtree_control` is EMPTY. memory/pids/cpu files never materialize; limits silently no-op. `demo-resource-limits.ts` confirms that memory/PID/CPU bombs ran with no enforcement before the workaround. Upstream: **canyonroad/agentsh#197**.
- **Isolation 15/15** (`capability-drop ✓`): the server process still has the full capability set. Either capability-drop only applies to spawned commands (in which case the detect label is misleading about what "active" means on the server) or the drop is a no-op. Upstream: **canyonroad/agentsh#198**.

### Workarounds applied in this repo

1. **`config.yaml`** sets `sandbox.cgroups.base_path: /sys/fs/cgroup/agentsh` — moves per-command cgroups out of the service slice and into a fresh tree where controllers ARE delegated. With this in place, `npm run demo:resources` reports: PID limit fires at 98/150 processes, memory bomb triggers OOM kill, CPU quota active, command timeout enforced. Only `disk_write_bps_max` remains unenforced — the `io` controller is not in the root `cgroup.subtree_control` on this kernel.
2. **`agentsh-startup.sh`** pre-creates `/sys/fs/cgroup/agentsh` and populates its `cgroup.subtree_control` with `+memory +pids +cpu +io` before starting the server — belt-and-braces in case agentsh doesn't initialize the tree.
3. **`config.yaml`** leaves `sandbox.network.ebpf.enabled: false` with an inline comment. This is a one-line flip once #196 lands.

### Diagnostic tooling

- `npm run diag:kernel:bare` — spin up a bare Freestyle VM (no agentsh) and probe the kernel directly
- `npm run diag:kernel:agentsh` — same probe on an agentsh-provisioned VM, then run `agentsh detect` and inspect `/proc/<server-pid>/status` for a side-by-side comparison
- `npm run diag:kernel` — run both modes

Future investigations into "is it the kernel or is it agentsh?" should start with these scripts before filing further upstream bugs.
