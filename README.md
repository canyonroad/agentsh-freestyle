# agentsh + Freestyle

Runtime governance for AI agents on [Freestyle](https://freestyle.sh) VMs. agentsh intercepts every command, file operation, and network call an agent makes — blocking dangerous actions, filtering secrets from the environment, quarantining deleted files, and producing a full audit trail. Freestyle provides fast, snapshot-based VM isolation so each agent runs in a clean, disposable sandbox.

## Quick Start

```bash
npm install
cp .env.example .env
# Add your Freestyle API key to .env
npx tsx src/demo-blocking.ts
```

## Protection Score: 80/100

`agentsh detect` reports which kernel security features are available and assigns a protection score. On the current Freestyle kernel (`6.1.0-6-freestyle`):

| Layer | Score | Backend | What It Does |
|---|---|---|---|
| **Command Control** | 25/25 | seccomp-execve | Intercepts every `execve` — blocks sudo, ssh, kill, rm -rf, etc. |
| **File Protection** | 25/25 | FUSE (fusermount) | Workspace-scoped virtual filesystem — soft-delete, redirect, audit |
| **Resource Limits** | 15/15 | cgroups-v2 | CPU, memory, PID, and I/O caps per command |
| **Isolation** | 15/15 | capability-drop | Drops all Linux capabilities not in the allowlist |
| **Network** | 0/20 | *(none)* | eBPF needs CAP_BPF; Landlock network needs kernel 6.7+ |

### What works

- **Command blocking** — the session API evaluates every command against `command_rules` before execution. 12 rule categories (privilege escalation, network tools, system commands, recursive delete, etc.) with named policy rules in the response.
- **Workspace file protection** — FUSE mounts a per-session overlay at the workspace path. File rules (allow, deny, soft-delete, approve) are enforced for all operations inside the workspace. Deleted files are quarantined and recoverable.
- **Environment filtering** — secrets (`AWS_*`, `OPENAI_API_KEY`, `DATABASE_URL`, etc.) are stripped; only allowlisted variables are passed through. Enumeration (`env`, `printenv`) is blocked.
- **Audit logging** — every command, file operation, and network call is logged to SQLite with session/command IDs, policy decisions, and resource usage.
- **Network policy** — embedded proxy intercepts outbound connections. Package registries allowed; metadata endpoints and private networks blocked.

### What requires kernel changes (for Freestyle engineers)

The Freestyle kernel (`6.1.0-6-freestyle`) is compiled with `capability,selinux` LSMs only. Three security features require kernel-level changes:

| Feature | What It Would Add | Kernel Requirement |
|---|---|---|
| **Landlock** | Full-filesystem file_rules enforcement (not just workspace) | `CONFIG_SECURITY_LANDLOCK=y` + `landlock` in LSM list |
| **Yama** | Enables seccomp file_monitor via ProcessVMReadv | `CONFIG_SECURITY_YAMA=y` + `yama` in LSM list |
| **eBPF (network)** | Per-cgroup network monitoring and filtering | `CAP_BPF` granted to the agentsh process |

**Why this matters:** Without Landlock, `file_rules` in `default.yaml` are only enforced inside the FUSE workspace mount — reads/writes to system paths like `/etc/shadow`, `/proc/1/environ` are not intercepted. With Landlock enabled, agentsh can enforce deny/allow decisions on **all** filesystem paths, not just the workspace. This would bring the protection score to 80+/100 and close the filesystem gap.

**Landlock is the highest-impact change.** The kernel is 6.1.0, which supports Landlock ABI v2 — the feature is available, it just needs `CONFIG_SECURITY_LANDLOCK=y` at kernel compile time and `landlock` appended to the `lsm=` boot parameter.

**Seccomp file_monitor** is an alternative to Landlock for file enforcement. It uses seccomp-notify to intercept `openat`/`stat` syscalls and ProcessVMReadv to read path arguments. This requires Yama (`CONFIG_SECURITY_YAMA=y`). Note: enabling both FUSE and seccomp file_monitor simultaneously causes a conflict — the server auto-disables seccomp openat emulation when FUSE is active, leaving seccomp filters in deny-all state. Use one or the other, not both.

**cgroup write access** is also currently restricted. The agentsh process cannot write to `/sys/fs/cgroup/.../memory.max` etc., so per-command resource limits (memory, CPU, PID) are logged but not enforced. Granting write access to the session's cgroup subtree would fix this.

## Demos

| Command | What It Shows |
|---|---|
| `npm run demo:blocking` | Command blocking (sudo, ssh, kill, rm -rf) + workspace file access |
| `npm run demo:detect` | Kernel capability detection — shows protection score and active backends |
| `npm run demo:network` | Network policy — localhost allowed, metadata/private networks blocked |
| `npm run demo:audit` | Audit trail — queries SQLite event log for command history |
| `npm run demo:quarantine` | Soft-delete — workspace deletes quarantine files; list/restore them |
| `npm run demo:env` | Environment filtering — secrets stripped, safe vars passed through |
| `npm run demo:attack` | Red team simulation — 44 attacks across recon, privesc, lateral movement, exfiltration |
| `npm run demo:resources` | Resource limits — PID bomb, memory bomb, CPU spin, I/O flood |
| `npm run demo:multi-context` | Bypass resistance — blocking via env vars, xargs, find -exec, Python subprocess |
| `npm run demo:fuse` | FUSE/VFS file protection — symlink escape blocking, Python I/O interception |
| `npm test` | Full test suite — 76 tests across 12 categories |

## Architecture

### Execution Model

The integration uses the agentsh HTTP session API (`POST /api/v1/sessions/{id}/exec`), not the shell shim, for command execution. This is important:

- **`execDirect(command, args)`** — sends the command directly to the session API. The server evaluates it against `command_rules` and returns `E_POLICY_DENIED` with exit code 126 for blocked commands. Use this for policy enforcement testing.
- **`exec(command)`** — wraps in `/bin/bash.real -c "..."` for shell features (pipes, redirections, variable expansion). The session API only sees `bash.real` as the top-level command, so sub-commands within bash are **not** evaluated against `command_rules`.

The distinction matters: `execDirect('sudo', ['whoami'])` is blocked by `block-shell-escape`. But `exec('sudo whoami')` runs `sudo` inside bash.real, which bypasses command_rules and actually executes.

### VmAgentsh Integration

`VmAgentsh` extends the Freestyle SDK's `VmWith<VmAgentshInstance>`:

```
VmSpec
  └─ .with('agentsh', new VmAgentsh())
       ├─ configureSnapshotSpec()  ← installs .deb, creates dirs, sudo rules (runs once during bake)
       └─ configureSpec()          ← uploads config/policy/startup, registers systemd service (every VM)
```

The startup sequence:
1. `install-agentsh.service` (oneshot) — installs the `.deb` package from GitHub releases
2. `agentsh.service` — starts the server, waits for health, installs the shell shim, warms up
3. `waitReady()` — polls health endpoint AND verifies `/bin/bash.real` exists (shim installed)

### Session API Flow

```
exec("sudo whoami")
  → ensureSession() → POST /api/v1/sessions {workspace: "/home/user"}
  → sessionExec()   → POST /api/v1/sessions/{id}/exec {command, args}
  ← response        → {result: {exit_code, stdout, stderr},
                        events: {blocked_operations, file_operations},
                        guidance: {policy_rule}}
```

## Config Files

| File | Purpose |
|---|---|
| `config.yaml` | Server settings — HTTP/gRPC addresses, session limits, FUSE/seccomp/cgroup toggles, audit storage, DLP patterns |
| `default.yaml` | Security policy (~640 lines) — file rules, network rules, command rules, env policy, resource limits |
| `agentsh-startup.sh` | Bootstrap — restricts `/dev/fuse`, starts server, installs shell shim, keeps service alive |

## Security Policy (`default.yaml`)

Default-deny posture with explicit allowlists.

**File rules (18 rules)** — workspace read/write with soft-delete for deletes; `/tmp` full access; system paths read-only; credential paths (`~/.ssh`, `~/.aws`, `.env`) require approval; everything else denied.

**Network rules (11 rules)** — localhost allowed; package registries (npm, PyPI, crates.io, Go proxy) allowed on 443; cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`) blocked; private networks (RFC 1918) blocked; all other destinations denied.

**Command rules (10 rules)** — standard POSIX tools and dev tools allowed; privilege escalation (sudo, su, chroot, nsenter) blocked; network tools (ssh, nc, socat) blocked; system commands (kill, shutdown, systemctl, dd) blocked; recursive delete blocked; infrastructure commands (iptables, ip, tc) blocked.

**Environment policy** — allowlist: PATH, HOME, NODE_ENV, GIT_*, PYTHONPATH, etc. Denylist: AWS_*, OPENAI_API_KEY, DATABASE_URL, SECRET_*, TOKEN*, etc. Max 100 keys, 64KB total, enumeration blocked.

**Resource limits** — 2GB memory (no swap), 50% CPU, 100 PIDs, 50MB/s read / 25MB/s write, 5min command timeout, 1hr session timeout.

## Related

- [agentsh](https://github.com/erans/agentsh) — the agentsh runtime governance tool
