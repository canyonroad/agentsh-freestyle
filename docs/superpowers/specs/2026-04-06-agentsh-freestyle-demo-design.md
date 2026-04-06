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
│   ├── test-template.ts            # Comprehensive test suite (~76 tests)
│   ├── build-snapshot.ts           # Image baking: creates agentsh snapshot
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
  //   - agentsh-server (service): runs agentsh server daemon
  //   - agentsh-shim (oneshot, after server): installs shell shim + warmup
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

1. `agentsh-server` (service mode): runs `agentsh server` daemon with logging to `/var/log/agentsh/server.log`
2. `agentsh-shim` (oneshot, after agentsh-server): installs shell shim via `agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash`, warms up with `echo shim warmup ok`

### Startup script (`agentsh-startup.sh`)

- Sets `AGENTSH_SHIM_FORCE=1` env var
- Sets FUSE device permissions (`chmod 666 /dev/fuse` if available)
- Starts agentsh server with logging
- Health check loop on `http://127.0.0.1:18080/health`
- Shell shim installation and warmup

### Image baking (`build-snapshot.ts`)

Alternative approach for faster startup:
1. Creates a VM via VmSpec with agentsh fully installed
2. Waits for readiness
3. Calls `vm.snapshot()` to capture the state
4. Prints snapshot ID for reuse
5. Users can then create VMs from snapshot ID, skipping installation

## Test Suite (test-template.ts)

~76 tests across 12 categories:

| Category | Count | What it validates |
|---|---|---|
| Installation | 2 | agentsh binary exists, seccomp support |
| Server & Config | 5 | Server healthy, process running, policy/config files exist, FUSE enabled |
| Shell Shim | 4 | Shim installed, real bash preserved, echo/python through shim |
| Policy Evaluation | 9 | Static policy-test CLI (sudo denied, echo allowed, workspace write, soft-delete, SSH approval) |
| Security Diagnostics | 7 | `agentsh detect` — seccomp, cgroups_v2, landlock availability |
| Command Blocking | 6 | sudo, su, ssh, kill, rm -rf blocked; echo allowed |
| Network Blocking | 5 | npmjs allowed, metadata blocked, evil.com blocked, private networks blocked |
| Environment Policy | 5 | Sensitive vars filtered, HOME/PATH present, BASH_ENV set, env enumeration blocked |
| File I/O | 6 | Workspace writes allowed, /etc writes blocked, symlink escape blocked |
| Multi-context | 7 | env/xargs/find -exec/python subprocess blocking |
| FUSE Workspace | 4 | FUSE mounted, soft-delete, file recovery, symlink escape |
| Credential Blocking | 3 | ~/.ssh, ~/.aws, /proc/1/environ blocked |

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
