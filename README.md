# agentsh + Freestyle

Runtime governance for AI agents on [Freestyle](https://freestyle.sh) VMs. agentsh intercepts every command, file operation, and network call an agent makes — blocking dangerous actions, filtering secrets from the environment, quarantining deleted files, and producing a full audit trail. Freestyle provides fast, snapshot-based VM isolation so each agent runs in a clean, disposable sandbox.

## Quick Start

```bash
npm install
cp .env.example .env
# Add your Freestyle API key to .env
npx tsx src/demo-blocking.ts
```

## What's working on Freestyle today (agentsh v0.18.0, kernel 6.1.0-7-freestyle)

| Layer | Backend | Status | Notes |
|---|---|---|---|
| **Command Control** | seccomp-execve + session API | ✅ | Blocks sudo, ssh, kill, rm -rf, etc. |
| **Workspace files** | FUSE (per-session overlay) | ✅ | Soft-delete, redirect, audit |
| **System path files** | Landlock ABI v2 | ✅ NEW | Applied per-command via `agentsh-unixwrap` |
| **Network policy** | userspace proxy + Landlock | ✅ | eBPF cgroup/connect path is OFF (see below) |
| **Capability drop** | capability(7) | ✅ | Honest reporting since v0.18.0 (#198) |
| **Memory limit + cmd timeout** | systemd + agentsh server | ✅ | OOM kills work; 5s timeouts trip |
| **PID / CPU / disk I/O caps** | cgroups v2 (top-level fallback) | ⚠️ | Slice & per-cmd cgroups exist, processes never get migrated into them — see "Resource limit gap" |
| **eBPF cgroup/connect hooks** | cilium/ebpf CO-RE | ❌ | Freestyle kernel ships without BTF (see "eBPF gap") |
| **Landlock network ABI** | Landlock ABI v4 | ❌ | Needs kernel 6.7+; Freestyle is on 6.1 |

The test suite (`npm test`) runs **64 assertions across 14 categories** and on a clean run lands at **64/64 passing**. The "PID limit" check is intentionally written to document the resource-limit gap rather than red-fail it; if/when agentsh starts moving spawned processes into the per-command cgroup, the test should be tightened.

## What v0.18.0 changed (vs v0.16.9)

| Area | v0.16.9 (old) | v0.18.0 (now) |
|---|---|---|
| **Landlock** | Not in Freestyle kernel — file_rules for system paths were a no-op | Kernel 6.1+ ships Landlock; agentsh applies an auto-derived ruleset per command via `agentsh-unixwrap`. `/etc` writes, `/proc/1/environ` reads, `/usr/bin` overwrites are now blocked at the kernel. |
| **eBPF detect (#196)** | `agentsh detect` reported "permission denied" on a kernel that actually had CAP_BPF — false negative | Detect is fixed (#199), but agentsh's stricter capability check now refuses to start when `ebpf.enabled=true` because Freestyle's kernel ships **without BTF** (`/sys/kernel/btf/vmlinux` missing). cilium/ebpf CO-RE programs literally cannot load. We leave `sandbox.network.ebpf.enabled: false` and document this; the userspace proxy + Landlock cover the network gate. |
| **Cgroup nested-mode (#197)** | Memory/PID/CPU caps silently no-op'd because the freestyle-supervisor.service slice has empty `subtree_control`. Worked around with a manual `base_path` override that pre-created `/sys/fs/cgroup/agentsh` and shoved controllers into its `subtree_control`. | `ProbeCgroupsV2` (#202/#214) auto-detects the empty nested cgroup and falls back to a top-level `/sys/fs/cgroup/agentsh.slice`. The slice is created and per-command sub-cgroups appear automatically — **no manual workaround in `agentsh-startup.sh` anymore**. (See "Resource limit gap" for the remaining issue.) |
| **Capability-drop scoring (#198)** | Reported `15/15 capability-drop ✓` while `CapEff = 0x1ffffffffff` (all caps set) — cosmetic but misleading | Honest reporting in v0.18.0 (#200). Score went from a fictitious 80/100 to a real ~65/100, but actual containment is **better** because Landlock now enforces system paths. The lower number is more truthful. |
| **Landlock derivation (#209)** | N/A | Wildcard ops + MAKE_SOCK fixed in v0.18.0, so policy `file_rules` with `operations: ["*"]` correctly feed paths into the auto-derived Landlock ruleset. |

## What's verified end-to-end

**Command blocking (session API)** — every command is evaluated against `command_rules` before execution:

| Rule | Commands Blocked |
|---|---|
| `block-shell-escape` | sudo, su, chroot, nsenter, unshare |
| `block-network-tools` | ssh, nc, netcat, socat |
| `block-system-commands` | kill, shutdown, reboot, systemctl, dd |
| `block-rm-recursive` | rm -rf, rm -r, rm --recursive |
| `block-infrastructure-interference` | iptables, ip, tc |

**Workspace file protection (FUSE)** — per-session overlay at `/home/user`:
- Read/write intercepted and audited
- Deletes converted to soft-delete (quarantined, not destroyed)
- Python/language-runtime I/O caught at the VFS level (bypasses shell, still intercepted)
- `/tmp` is writable but not FUSE-protected (deletes are permanent)

**System path enforcement (Landlock — NEW)** — `agentsh-unixwrap` applies a Landlock ruleset to every wrapped command. Verified:
- Writes to `/etc`, `/usr/bin`, `/proc/sys/kernel` → EACCES from kernel
- Reads of `/proc/1/environ`, `/proc/1/cmdline` → EACCES from kernel
- Test: `unixwrap applies Landlock to session commands` checks for `landlock: restrictions applied (abi=2, ...)` in stderr

**Environment filtering** — `libenvshim.so` via `LD_PRELOAD` strips `AWS_*`, `OPENAI_API_KEY`, `DATABASE_URL`, `SECRET_*`, `*_TOKEN`, `*_PASSWORD`. Session env is minimal (~18 vars). `FREESTYLE_API_KEY` is not leaked.

**Network policy** — embedded proxy enforces:
- Localhost (`127.0.0.1`) → allowed
- Package registries (npmjs.org, pypi.org, crates.io) → allowed on 443
- Cloud metadata (`169.254.169.254`, `100.100.100.200`) → blocked
- Private networks (10.x, 172.16.x, 192.168.x) → blocked
- Unknown / malicious domains → blocked

**Audit logging** — every command, file op, and network call → SQLite at `/var/lib/agentsh/events.db`. Queryable via `sqlite3` or `agentsh events query --direct-db`.

**Red team attack simulation** — `npm run demo:attack` runs 44 attacks across 7 phases. Current result on v0.18.0: **41 blocked / 3 allowed (93%)**. The 3 that get through are all in Phase 1 (recon): `/etc/passwd`, `/etc/shadow`, environment dump. The Landlock ruleset is auto-derived from policy `file_rules` base directories, so `/etc/shadow` inherits the same `/etc` allow that `/etc/passwd` and `/etc/hosts` need. To carve those out you'd need a finer-grained Landlock derivation than the current base-dir extraction.

| Phase | Attacks | Blocked | What got through |
|---|---|---|---|
| Reconnaissance | 7 | 4 | /etc/passwd, /etc/shadow, env dump |
| Credential Theft | 7 | 7 | — |
| Privilege Escalation | 6 | 6 | — |
| Lateral Movement | 6 | 6 | — |
| Data Exfiltration | 5 | 5 | — |
| Persistence | 5 | 5 | — |
| Destruction | 8 | 8 | — |

(Phase 6 went from 2/5 blocked → 5/5 blocked once Landlock landed.)

## The remaining gaps

### Resource limit gap — `pids_max` / `cpu.max` / `io.max` not enforced

v0.18.0's top-level cgroup fallback (#202/#214) creates `/sys/fs/cgroup/agentsh.slice` and per-command sub-cgroups under it. The directories appear, the controllers are enabled in `cgroup.subtree_control`, everything looks correct. But:

1. agentsh runs as its own systemd service (`/system.slice/agentsh.service`)
2. Commands invoked via `vm.exec` (the Freestyle SDK call that drives our session API curls) end up under `/system.slice/freestyle-supervisor.service`
3. The agentsh server creates a per-command cgroup but **does not migrate the spawned process into it**
4. A workaround that moves the agentsh server PID into `agentsh.slice` from `agentsh-startup.sh` is rejected by the kernel — once `subtree_control` has controllers, the cgroup can't have processes directly in it ("no internal process constraint" → I/O error on the write)

Net effect: `pids_max=100` / `cpu.max=50%` / `io.max=25MB/s` from `default.yaml` are silently no-ops on Freestyle. Memory and command-timeout still trip via systemd / agentsh server side enforcement, so they appear as ENFORCED in `npm run demo:resources`.

The test suite documents this gap explicitly:
```
PID limit (resource_limits.pids_max=100, NOT enforced — agentsh#?)... ✓ PASS
```
The test passes by intentionally accepting the gap; if agentsh starts migrating processes into per-command cgroups, the test should be tightened to actually check `forked < 150`.

### eBPF gap — kernel ships without BTF

`/sys/kernel/btf/vmlinux` is missing on Freestyle's kernel build. cilium/ebpf relies on BTF for CO-RE relocation; without it, agentsh's eBPF programs cannot load. v0.18.0's stricter capability check refuses to start when `sandbox.network.ebpf.enabled: true` is set in this state, so we keep it OFF and let the userspace proxy + Landlock cover the network gate.

**Verified independently** on `6.1.0-7-freestyle` (run `npm run diag:ebpf` to reproduce):

- `/sys/kernel/btf/vmlinux` — `No such file or directory`
- `/sys/kernel/btf/` — entire directory missing
- `find / -name 'btf' -type d` — empty
- `bpftool btf list` — empty (kernel knows about zero BTF objects)
- Raw `bpf(BPF_BTF_GET_NEXT_ID, ...)` syscall — returns ENOENT
- `agentsh detect` (v0.18.0) — `ebpf - btf not present (missing /sys/kernel/btf/vmlinux)`
- Forcing `ebpf.enabled: true` — agentsh server exits with `capability check failed / Feature: ebpf / To fix: ... or upgrade to a kernel that supports this feature`

For Freestyle engineers: enabling `CONFIG_DEBUG_INFO_BTF=y` (and ideally `CONFIG_DEBUG_INFO_BTF_MODULES=y`) in the kernel build would let agentsh's eBPF cgroup/connect hooks load and run.

### Landlock derivation is base-directory granular

Auto-derivation collapses each policy `file_rules` path at the first glob character (`extractBaseDir`). `/etc/passwd`, `/etc/hosts`, `/etc/resolv.conf`, etc. all get added as a single `/etc` allow — which means `/etc/shadow` (in `deny_paths`) is also readable, because Landlock has no carve-out semantics inside an allowed parent.

The same coarseness lets `sudo` execute when invoked via `bash.real -c "sudo whoami"` (the binary is at `/usr/bin/sudo`, which inherits the `/usr/bin` execute allow that legitimate tools need).

Tightening this requires either a more granular Landlock derivation in agentsh (tracking individual files instead of base dirs) or scaling the policy down to list every individual file you want allowed.

### Commands within `bash.real` bypass `command_rules`

The session API only evaluates the top-level command. `agentsh.exec("sudo whoami")` runs through `bash.real -c "sudo whoami"`, so `bash.real` is the command the policy sees — not `sudo`. Sub-commands within bash are unevaluated. Combined with the Landlock base-dir issue above, `sudo whoami` actually succeeds inside bash on this VM (which runs as root).

Use `agentsh.execDirect('sudo', ['whoami'])` for command-policy enforcement testing — that path IS blocked by `block-shell-escape`.

The `demo:multi-context` demo shows this distinction explicitly.

## Demos

| Command | What It Shows |
|---|---|
| `npm run demo:blocking` | Command blocking + workspace + system path access |
| `npm run demo:detect` | Kernel capability detection — protection score and active backends |
| `npm run demo:network` | Network policy — localhost allowed, metadata/private networks blocked |
| `npm run demo:audit` | Audit trail — queries SQLite event log |
| `npm run demo:quarantine` | Soft-delete — workspace deletes quarantine files |
| `npm run demo:env` | Environment filtering — secrets stripped, safe vars passed through |
| `npm run demo:attack` | Red team simulation — 44 attacks across recon/privesc/lateral/exfil (93% blocked) |
| `npm run demo:resources` | Resource limits — PID bomb, memory bomb, CPU spin, I/O flood, cgroup status |
| `npm run demo:multi-context` | Command enforcement model — direct API blocking vs bash sub-process behavior |
| `npm run demo:fuse` | FUSE workspace + Landlock system path enforcement |
| `npm test` | Full test suite — 64 tests across 14 categories |
| `npm run diag:kernel` | Ground-truth kernel probe — bare VM AND agentsh-provisioned VM side by side |
| `npm run diag:kernel:bare` | Bare VM only (no agentsh) |
| `npm run diag:kernel:agentsh` | agentsh-provisioned VM only, plus `agentsh detect` |
| `npm run diag:ebpf` | Focused eBPF/BTF probe — verifies the BTF-missing claim and forces `ebpf.enabled: true` to capture agentsh's actual gate error. Re-run after Freestyle ships a new kernel. |

## Architecture

### Execution Model

The integration uses the agentsh HTTP session API (`POST /api/v1/sessions/{id}/exec`), not the shell shim, for command execution.

- **`execDirect(command, args)`** — sends the command directly to the session API. The server evaluates it against `command_rules` and returns `E_POLICY_DENIED` (exit 126) for blocked commands. Use this for policy enforcement testing.
- **`exec(command)`** — wraps in `/bin/bash.real -c "..."` for shell features (pipes, redirections, expansions). The session API only sees `bash.real` as the top-level command, so sub-commands within bash are **not** evaluated against `command_rules` (but Landlock still applies via unixwrap).

### VmAgentsh Integration

`VmAgentsh` extends the Freestyle SDK's `VmWith<VmAgentshInstance>`:

```
VmSpec
  └─ .with('agentsh', new VmAgentsh())
       ├─ configureSnapshotSpec()  ← installs .deb, creates dirs, sudo rules (runs once during bake)
       └─ configureSpec()          ← uploads config/policy/startup, registers systemd service (every VM)
```

Startup sequence:
1. `install-agentsh.service` (oneshot) — installs the v0.18.0 `.deb` from GitHub releases
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

`sessionExec` retries once on transient empty/invalid responses — the curl-over-localhost path occasionally returns empty stdout under load, and a single retry makes the suite stable.

## Config Files

| File | Purpose |
|---|---|
| `config.yaml` | Server settings — HTTP/gRPC, sessions, FUSE/seccomp/cgroup toggles, audit, DLP. Top-level `landlock:` block lists allow/deny paths as defence-in-depth. `sandbox.network.ebpf.enabled: false` because Freestyle kernel lacks BTF. `sandbox.cgroups` has no manual `base_path` — v0.18.0 auto-falls-back to `/sys/fs/cgroup/agentsh.slice`. |
| `default.yaml` | Security policy (~640 lines) — file rules, network rules, command rules, env policy, resource limits |
| `agentsh-startup.sh` | Bootstrap — restricts `/dev/fuse` (deferred FUSE), starts agentsh server, installs shell shim, keeps service alive. No manual cgroup setup since v0.18.0 auto-detects. |
| `src/diag-kernel.ts`, `src/diag-kernel.sh` | Ground-truth kernel capability probe — `cat /proc/*/status`, `bpftool feature probe`, raw `bpf()`/`seccomp()` syscalls, cgroup controller enumeration. Use before filing upstream bugs. |

## Security Policy (`default.yaml`)

Default-deny posture with explicit allowlists.

**File rules** — workspace read/write with soft-delete for deletes; `/tmp` full access; system paths read-only; credential paths (`~/.ssh`, `~/.aws`, `.env`) require approval; everything else denied.

**Network rules** — localhost allowed; package registries (npm, PyPI, crates.io, Go proxy) allowed on 443; cloud metadata endpoints blocked; private networks (RFC 1918) blocked; default deny.

**Command rules** — standard POSIX tools and dev tools allowed; privilege escalation (sudo, su, chroot, nsenter) blocked; network tools (ssh, nc, socat) blocked; system commands (kill, shutdown, systemctl, dd) blocked; recursive delete blocked; infrastructure commands (iptables, ip, tc) blocked.

**Environment policy** — allowlist: PATH, HOME, NODE_ENV, GIT_*, PYTHONPATH, etc. Denylist: AWS_*, OPENAI_API_KEY, DATABASE_URL, SECRET_*, TOKEN*, etc. Max 100 keys, 64KB total, enumeration blocked.

**Resource limits** — 2GB memory (no swap), 50% CPU, 100 PIDs, 50/25 MB/s disk I/O, 5min command timeout, 1hr session timeout. (Caveat: only memory and command timeout actually trip on Freestyle — see "Resource limit gap".)

## Related

- [agentsh](https://github.com/canyonroad/agentsh) — the agentsh runtime governance tool

### Upstream issue history (Freestyle integration)

| Issue | What it was | Status in v0.18.0 |
|---|---|---|
| **canyonroad/agentsh#196** | `agentsh detect` reported `ebpf - permission denied` on a kernel where CAP_BPF was present and raw `bpf(BPF_PROG_LOAD, ...)` worked | Detect logic fixed in #199. On Freestyle the eBPF backend is **still** off, but for a different reason: kernel ships without BTF (`/sys/kernel/btf/vmlinux` missing), so cilium/ebpf CO-RE programs cannot load. Filed as a Freestyle kernel-build follow-up. |
| **canyonroad/agentsh#197** | Resource limits silently no-op'd because agentsh placed per-command cgroups under a parent (`freestyle-supervisor.service`) whose `cgroup.subtree_control` was empty | `ProbeCgroupsV2` auto-fallback added in #202/#214 — agentsh now creates `/sys/fs/cgroup/agentsh.slice` and per-command sub-cgroups under it automatically. **Slice is created correctly**, but spawned processes are not migrated into the per-command cgroup, so PID/CPU/disk-IO caps still no-op. Memory and timeout still trip via the systemd / server-side path. Tracked as a v0.18.0 follow-up. |
| **canyonroad/agentsh#198** | Capability-drop scored 15/15 while `CapEff` was `0x1ffffffffff` (all caps) — cosmetic | Fixed (#200). Score is honest now. The total score going from "80/100" to "65/100" reflects truth-in-reporting, not regression — actual containment is **better** because Landlock now enforces system paths. |
| **canyonroad/agentsh#209** | Auto-derived Landlock ruleset dropped rules with `operations: ["*"]` and didn't include `MAKE_SOCK` | Fixed in v0.18.0. Wildcard ops are honored; the `socket(AF_UNIX)` test for unix-socket interception now works. |
