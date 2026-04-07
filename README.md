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

### What works (verified)

All protections below have been tested end-to-end on Freestyle VMs. The test suite (`npm test`) validates 58 assertions across 13 categories, all passing.

**Command blocking (via session API)** — the session API evaluates every command against `command_rules` before execution. Verified blocked commands with named policy rules:

| Rule | Commands Blocked |
|---|---|
| `block-shell-escape` | sudo, su, chroot, nsenter, unshare |
| `block-network-tools` | ssh, nc, netcat, socat |
| `block-system-commands` | kill, shutdown, reboot, systemctl, dd |
| `block-rm-recursive` | rm -rf, rm -r, rm --recursive |
| `block-infrastructure-interference` | iptables, ip, tc |

**Workspace file protection (FUSE)** — FUSE mounts a per-session overlay at the workspace path (`/home/user`). Verified:
- Read/write to workspace files intercepted and audited
- Deletes converted to soft-delete (files quarantined, not destroyed)
- Python/language-runtime I/O caught at the VFS level (bypasses shell, still intercepted)
- `/tmp` is writable but not FUSE-protected (deletes are permanent)

**Environment filtering** — `libenvshim.so` loaded via `LD_PRELOAD` intercepts `getenv`/`environ` calls. Verified:
- Session environment is minimal (18 variables)
- Sensitive patterns all filtered: `AWS_*`, `OPENAI_API_KEY`, `DATABASE_URL`, `SECRET_*`, `*_TOKEN`, `*_PASSWORD`
- Safe variables available: `PATH`, `HTTPS_PROXY`, `PWD`, `LANG`
- `FREESTYLE_API_KEY` not leaked to session

**Network policy (embedded proxy)** — proxy intercepts outbound HTTP/HTTPS connections. Verified:
- Localhost (`127.0.0.1`) — allowed
- Package registries (npmjs.org, pypi.org, crates.io) — allowed
- Cloud metadata (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`) — blocked (HTTP 403/connection refused)
- Private networks (10.x, 172.16.x, 192.168.x) — blocked
- Unknown/malicious domains (evil.com, example.com) — blocked

**Audit logging** — every command, file operation, and network call logged to SQLite (`/var/lib/agentsh/events.db`). Schema includes `event_id`, `ts_unix_ns`, `session_id`, `command_id`, `type`, `policy_decision`, `policy_rule`. Queryable via `sqlite3` or `agentsh events query --direct-db`.

**Red team attack simulation** — 44 attacks across 7 phases. Results: **36 blocked (82%), 8 allowed (18%)**. The 8 that got through are all system path access — the Landlock gap (see below).

| Phase | Attacks | Blocked | What Got Through |
|---|---|---|---|
| Reconnaissance | 7 | 2 | /etc/passwd, /etc/shadow, env, /proc/1/environ, /proc/1/cmdline |
| Credential Theft | 7 | 7 | — |
| Privilege Escalation | 6 | 6 | — |
| Lateral Movement | 6 | 6 | — |
| Data Exfiltration | 5 | 5 | — |
| Persistence | 5 | 2 | /etc/profile.d write, /usr/bin overwrite, ~/.bashrc inject |
| Destruction | 8 | 8 | — |

### What doesn't work (the gaps)

**Commands within bash.real bypass command_rules.** The session API only evaluates the top-level command. When using `exec()` (which wraps in `bash.real -c "..."`), sub-commands like `sudo`, `kill`, `ssh` are not evaluated — they run as child processes of bash. On Freestyle VMs, which run as root, this means:
- `sudo whoami` succeeds inside bash (root doesn't need a password)
- `kill -9 1` succeeds inside bash (root has permission)
- `env sudo whoami`, `xargs sudo`, `find -exec sudo`, Python `subprocess.run(['sudo', ...])` all succeed

The `demo:multi-context` demo shows this explicitly. For full sub-process enforcement, Landlock would prevent execution of blocked binaries regardless of how they are invoked.

**System paths are unprotected.** FUSE only covers the workspace path (`/home/user`). Without Landlock, reads and writes to `/etc`, `/usr`, `/var`, `/proc` are allowed by OS permissions (process runs as root). This is the source of all 8 "allowed" attacks in the red team simulation.

**cgroup write access denied.** agentsh cannot write to `/sys/fs/cgroup/.../memory.max`, `pids.max`, etc. Per-command resource limits (PID cap, I/O throttle) are configured in policy but not enforced at the cgroup level. VM-level limits from Freestyle still apply as a safety net (memory OOM kill and command timeout are verified working).

**Quarantine list incomplete.** FUSE soft-delete works (files vanish from original path), but `agentsh trash list` reports "trash empty". The quarantined files are stored in a session-specific path that the CLI doesn't find without session context. Restore functionality is blocked by this.

### What requires kernel changes (for Freestyle engineers)

The Freestyle kernel (`6.1.0-6-freestyle`) is compiled with `capability,selinux` LSMs only. The following changes would close the gaps above:

| Change | Impact | Requirement | Priority |
|---|---|---|---|
| **Landlock** | Closes ALL 8 attack gaps. Enforces file_rules on every filesystem path, not just workspace. Blocks execution of denied binaries in any context (bash, env, xargs, Python). | `CONFIG_SECURITY_LANDLOCK=y` + `landlock` in `lsm=` boot param | **Critical** |
| **cgroup subtree write** | Enables per-command PID limits, I/O throttle, memory caps | Grant write access to agentsh's cgroup subtree | High |
| **CAP_BPF** | Enables per-cgroup network monitoring via eBPF (+20 pts) | Grant `CAP_BPF` to agentsh process | Medium |
| **Yama** | Enables seccomp file_monitor as alternative to FUSE | `CONFIG_SECURITY_YAMA=y` + `yama` in LSM list | Low (Landlock preferred) |
| **Non-root execution** | OS permissions become a defense layer | Run agent process as unprivileged user | Medium |

**Landlock is the single highest-impact change.** The kernel is 6.1.0, which supports Landlock ABI v2 — the feature is available, it just needs `CONFIG_SECURITY_LANDLOCK=y` at kernel compile time and `landlock` appended to the `lsm=` boot parameter. This alone would:
- Block reads to `/etc/shadow`, `/proc/1/environ` (recon)
- Block writes to `/etc/profile.d`, `/usr/bin`, `~/.bashrc` (persistence)
- Block execution of `sudo`, `ssh`, `kill` binaries from any context (bash bypass)
- Bring the attack simulation to **44/44 blocked (100%)**

**Seccomp file_monitor** is an alternative to Landlock for file enforcement. It uses seccomp-notify to intercept `openat`/`stat` syscalls and ProcessVMReadv to read path arguments. This requires Yama (`CONFIG_SECURITY_YAMA=y`). Note: enabling both FUSE and seccomp file_monitor simultaneously causes a conflict — the server auto-disables seccomp openat emulation when FUSE is active, leaving seccomp filters in deny-all state. Use one or the other, not both.

## Demos

| Command | What It Shows |
|---|---|
| `npm run demo:blocking` | Command blocking (sudo, ssh, kill, rm -rf) + workspace file access |
| `npm run demo:detect` | Kernel capability detection — shows protection score and active backends |
| `npm run demo:network` | Network policy — localhost allowed, metadata/private networks blocked |
| `npm run demo:audit` | Audit trail — queries SQLite event log for command history |
| `npm run demo:quarantine` | Soft-delete — workspace deletes quarantine files; list/restore them |
| `npm run demo:env` | Environment filtering — secrets stripped, safe vars passed through |
| `npm run demo:attack` | Red team simulation — 44 attacks across recon, privesc, lateral movement, exfiltration (82% blocked) |
| `npm run demo:resources` | Resource limits — PID bomb, memory bomb, CPU spin, I/O flood, cgroup status |
| `npm run demo:multi-context` | Command enforcement model — direct API blocking vs bash sub-process behavior |
| `npm run demo:fuse` | FUSE workspace file protection — read/write, soft-delete, system path gap |
| `npm test` | Full test suite — 58 tests across 13 categories |

## Architecture

### Execution Model

The integration uses the agentsh HTTP session API (`POST /api/v1/sessions/{id}/exec`), not the shell shim, for command execution. This is important:

- **`execDirect(command, args)`** — sends the command directly to the session API. The server evaluates it against `command_rules` and returns `E_POLICY_DENIED` with exit code 126 for blocked commands. Use this for policy enforcement testing.
- **`exec(command)`** — wraps in `/bin/bash.real -c "..."` for shell features (pipes, redirections, variable expansion). The session API only sees `bash.real` as the top-level command, so sub-commands within bash are **not** evaluated against `command_rules`.

The distinction matters: `execDirect('sudo', ['whoami'])` is blocked by `block-shell-escape`. But `exec('sudo whoami')` runs `sudo` inside bash.real, which bypasses command_rules and actually executes (because the VM runs as root).

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
